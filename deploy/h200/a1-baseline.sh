#!/bin/bash
# h200 (lives in ~/snp): A1 = CC overhead. Phase S turned out impossible (the NVIDIA driver refuses a normal-mode GPU in a CVM); kept for the record.
# h200: A1 = CC overhead. P: plain VM + GPU3 in normal mode (unprotected baseline, mock attestation).
#       S: SNP VM + GPU3 in normal mode (does the driver even work? if so: GPU-CC cost alone).
#       R: GPU3 back to CC mode, production relaunch. Every phase logs; R always runs.
set -u
cd ~/snp
T=~/snp/gpu-admin-tools/nvidia_gpu_tools.py
PY=/opt/attestrag/venv/bin/python
SITE=/opt/attestrag/venv/lib/python3.12/site-packages
stop_vm() { pkill -f "[q]emu-system-x86_64 -name snpvm" || true; for i in $(seq 1 30); do pgrep -f "[q]emu-system-x86_64 -name snpvm" >/dev/null || break; sleep 2; done; }
kbs() { P=$(ss -ltnp 2>/dev/null | grep ":8800 " | sed -E 's/.*pid=([0-9]+).*/\1/'); [ -n "$P" ] && kill "$P"; sleep 1
        nohup venv/bin/python -m attestrag.kbs_server --policy "$1" --keys kbs-keys.json --listen 127.0.0.1:8800 ${2:-} > kbs.log 2>&1 < /dev/null & sleep 2; curl -fs http://127.0.0.1:8800/healthz >/dev/null && echo "kbs up with $1 ${2:-}"; }
wait_guest() { for i in $(seq 1 60); do ./g true 2>/dev/null && return 0; sleep 5; done; echo "GUEST-SSH-FAILED"; return 1; }
wait_node() { for i in $(seq 1 60); do curl -fs -m 3 http://127.0.0.1:8081/healthz >/dev/null 2>&1 && { echo "node up"; return 0; }; sleep 5; done; echo "NODE-NOT-UP"; return 1; }
bench() { for ds in en_refine zh_refine; do echo "--- $(date +%T) bench $1 $ds"; venv/bin/python rag_bench.py --node http://127.0.0.1:8081 --policy "$2" ${3:-} --dataset $ds --limit 100 --holdout 0.2 --seed 7 --sweep 1,2,4,8 --skip-ingest --out bench-$1-$ds.json 2>&1 | grep -E "connect=|ask 100/100|concurrency [0-9]+:|rror" ; done; }

phase_p() {
echo "== $(date +%T) P: stop production guest, GPU3 CC off"
stop_vm
sudo -n python3 $T --devices 44:00.0 --set-cc-mode=off --reset-after-cc-mode-switch 2>&1 | grep -iE "cc mode|error" | tail -2
sudo -n python3 $T --devices 44:00.0 --query-cc-mode 2>&1 | grep -iE "CC mode is" | tail -1
sudo -n chown weiwang /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; sudo -n chmod 660 /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null
kbs policies-insecure-baseline.json --insecure-mock
GPU=0000:44:00.0 setsid nohup ./launch-snpvm.sh plain </dev/null > snpvm.console.log 2>&1 &
wait_guest || return 1
./g -c attestrag-pkg-overlay.tgz /tmp/pkg.tgz
./g "sudo tar xzf /tmp/pkg.tgz -C $SITE && sudo sed -i 's|^NODE_ARGS=|NODE_ARGS=--attester mock-insecure |' /etc/attestrag/node.env && sudo systemctl restart attestrag-node; sleep 3; grep -c mock-insecure /etc/attestrag/node.env; sudo dmesg | grep -c 'SEV' ; nvidia-smi conf-compute -q | grep -E 'CC State|CPU CC'; nvidia-smi --query-gpu=memory.used --format=csv,noheader"
wait_node || { ./g "sudo journalctl -u attestrag-node -n 6 --no-pager -o cat | cut -c1-160"; }
./g "sudo journalctl -u attestrag-node -n 4 --no-pager -o cat | cut -c1-140"
bench plain7b policies-insecure-baseline.json --insecure-mock
}

phase_s() {
echo "== $(date +%T) S: SNP VM with GPU3 still in normal mode"
stop_vm
python3 -c "import json; d=json.load(open('policy-h200.json')); d['require_gpu']=False; json.dump(d, open('policy-h200-nogpu.json','w'), indent=2)"
kbs policy-h200-nogpu.json
GPU=0000:44:00.0 setsid nohup ./launch-snpvm.sh snp </dev/null > snpvm.console.log 2>&1 &
if wait_guest; then
  ./g "sudo dmesg | grep -iE 'NVRM|nvidia' | grep -viE 'drm|nvlink' | tail -6 | cut -c1-180; nvidia-smi conf-compute -q 2>&1 | grep -E 'CC State|CPU CC' ; nvidia-smi --query-gpu=memory.used --format=csv,noheader 2>&1 | tail -1; systemctl is-active llama-chat attestrag-node | tr '\n' ' '; echo"
  if wait_node; then bench snp-plaingpu7b policy-h200-nogpu.json; else ./g "sudo journalctl -u attestrag-node -n 6 --no-pager -o cat | cut -c1-160; sudo journalctl -u llama-chat -n 4 --no-pager -o cat | cut -c1-160"; fi
fi
}

phase_p || echo "PHASE-P-FAILED"
phase_s || echo "PHASE-S-FAILED"
echo "== $(date +%T) R: GPU3 back to CC mode, production relaunch"
stop_vm
sudo -n python3 $T --devices 44:00.0 --set-cc-mode=on --reset-after-cc-mode-switch 2>&1 | grep -iE "cc mode|error" | tail -2
sudo -n python3 $T --devices 44:00.0 --query-cc-mode 2>&1 | grep -iE "CC mode is" | tail -1
sudo -n chown weiwang /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; sudo -n chmod 660 /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null
GPU=0000:44:00.0 bash relaunch.sh 2>&1 | grep -E "kbs up|qemu up|index has|allowed=" | head -4
./g "nvidia-smi conf-compute -q | grep -E 'CC State|Ready'; systemctl is-active attestrag-node"
echo "A1-DONE $(date +%T)"
