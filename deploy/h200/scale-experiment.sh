#!/bin/bash
# h200 (lives in ~/snp as scale.sh): CC overhead vs generator size. Needs scale-bench.py (guest microbenchmark) and scale-analyze.py (table) next to it.
# h200: CC overhead vs generator size. Same step-14 image; the chat model is switched in the tmpfs overlay.
# Phase A (GPU in CC mode, SEV-SNP guest, current production): 80b 14b 7b 1.5b. Phase B: same in a plain VM with
# the GPU in normal mode. Then back to production. Outputs: scale-<cfg>-<model>.json (microbench), bench-scale-<cfg>-<model>-<ds>.json.
set -u
cd ~/snp
G="./g"; T=~/snp/gpu-admin-tools/nvidia_gpu_tools.py
declare -A F=([1.5b]=qwen2.5-1.5b-instruct-q4_k_m.gguf [7b]=qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf [14b]=qwen2.5-14b-instruct-q4_k_m-00001-of-00003.gguf [80b]=Qwen3-Next-80B-A3B-Instruct-Q4_K_M.gguf)
switch_model() {  # $1 model key
  $G "sudo sed -i 's|-m /opt/llm/models/[^ ]*|-m /opt/llm/models/${F[$1]}|' /etc/systemd/system/llama-chat.service; sudo systemctl daemon-reload; sudo systemctl restart llama-chat"
  for i in $(seq 1 90); do $G "curl -fs -m 5 http://127.0.0.1:8091/v1/models >/dev/null" 2>/dev/null && break; sleep 5; done
  $G "grep -o 'models/[^ ]*' /etc/systemd/system/llama-chat.service; nvidia-smi --query-gpu=memory.used --format=csv,noheader"
}
run_model() {  # $1 cfg (cvm|plain), $2 model, $3 policy, $4 extra client args
  echo "== $(date +%T) $1 $2"; switch_model $2
  $G "python3 /tmp/scale-bench.py $2" > scale-$1-$2.json 2>scale-$1-$2.err; cut -c1-200 scale-$1-$2.json
  for ds in en_refine zh_refine; do
    venv/bin/python rag_bench.py --node http://127.0.0.1:8081 --policy $3 $4 --dataset $ds --limit 100 --holdout 0.2 --seed 7 --sweep 1,8 --skip-ingest --out bench-scale-$1-$2-$ds.json 2>&1 | grep -E "ask 100/100|concurrency [0-9]+:|rror"
  done
}
$G -c scale-bench.py /tmp/scale-bench.py
echo "===== phase A: CVM + CC GPU ====="
for m in 80b 14b 7b 1.5b; do run_model cvm $m policy-h200.json "--gpu-rim"; done

echo "===== phase B: plain VM + GPU in normal mode ====="
pkill -f "[q]emu-system-x86_64 -name snpvm" || true; sleep 3
sudo -n python3 $T --devices 44:00.0 --set-cc-mode=off --reset-after-cc-mode-switch 2>&1 | grep -iE "cc mode is|error" | tail -1
sudo -n chown weiwang /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; sudo -n chmod 660 /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null
P=$(ss -ltnp 2>/dev/null | grep ":8800 " | sed -E 's/.*pid=([0-9]+).*/\1/'); [ -n "$P" ] && kill "$P"; sleep 1
nohup venv/bin/python -m attestrag.kbs_server --policy policies-insecure-baseline.json --keys kbs-keys.json --listen 127.0.0.1:8800 --insecure-mock > kbs.log 2>&1 < /dev/null &
GPU=0000:44:00.0 setsid nohup ./launch-snpvm.sh plain </dev/null > snpvm.console.log 2>&1 &
for i in $(seq 1 60); do $G true 2>/dev/null && break; sleep 5; done; $G true || { echo "PLAIN-SSH-FAILED"; }
$G "sudo sed -i 's|^NODE_ARGS=|NODE_ARGS=--attester mock-insecure |' /etc/attestrag/node.env; sudo systemctl restart attestrag-node"
for i in $(seq 1 60); do curl -fs -m 3 http://127.0.0.1:8081/healthz >/dev/null 2>&1 && break; sleep 5; done; echo "plain node: $(curl -s -m 3 http://127.0.0.1:8081/healthz)"
$G -c scale-bench.py /tmp/scale-bench.py
for m in 80b 14b 7b 1.5b; do run_model plain $m policies-insecure-baseline.json "--insecure-mock"; done

echo "===== restore: CC on, production relaunch ====="
pkill -f "[q]emu-system-x86_64 -name snpvm" || true; sleep 3
sudo -n python3 $T --devices 44:00.0 --set-cc-mode=on --reset-after-cc-mode-switch 2>&1 | grep -iE "cc mode is|error" | tail -1
sudo -n chown weiwang /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; sudo -n chmod 660 /dev/vfio/32 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null
GPU=0000:44:00.0 bash relaunch.sh 2>&1 | grep -E "kbs up|qemu up|released|allowed=" | head -4
$G "nvidia-smi conf-compute -q | grep -E 'CC State|Ready'"
echo "SCALE-DONE $(date +%T)"
