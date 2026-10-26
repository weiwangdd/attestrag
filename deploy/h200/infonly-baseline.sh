#!/bin/bash
# h200: "inference-only TEE" baseline. Retrieval node in a plain VM (same step-12 image, mock attestation,
# CPU embedding), generation calls forwarded over ssh into the production CVM's llama-chat (7B on the CC GPU).
# Leaves the production CVM untouched; everything else is torn down at the end.
set -u
cd ~/snp
G2="ssh -i snpvm_key -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ubuntu@127.0.0.1"
cleanup() {
  echo "== $(date +%T) cleanup"
  pkill -f "[q]emu-system-x86_64 -name plainvm" || true
  [ -n "${TUN:-}" ] && kill $TUN 2>/dev/null
  [ -n "${KBS2:-}" ] && kill $KBS2 2>/dev/null
  sleep 2; rm -f images/data-plain.qcow2
  echo "production node: $(curl -s -m 3 http://127.0.0.1:8081/healthz)"
}
trap cleanup EXIT
echo "== $(date +%T) data disk copy (sealed index, static)"; qemu/bin/qemu-img convert -U -O qcow2 images/data.qcow2 images/data-plain.qcow2 && ls -la images/data-plain.qcow2 | cut -c1-80
echo "== tunnel host:8191 -> CVM llama-chat :8091"
setsid nohup ssh -N -L 127.0.0.1:8191:127.0.0.1:8091 -i snpvm_key -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ubuntu@127.0.0.1 >/dev/null 2>&1 &
TUN=$!; sleep 2; curl -s -m 10 http://127.0.0.1:8191/v1/models | head -c 120; echo
echo "== second KBS :8801 (insecure baseline policy, same keys)"
setsid nohup venv/bin/python -m attestrag.kbs_server --policy policies-insecure-baseline.json --keys kbs-keys.json --listen 127.0.0.1:8801 --insecure-mock > kbs2.log 2>&1 < /dev/null &
KBS2=$!; sleep 2; curl -fs http://127.0.0.1:8801/healthz && echo " kbs2 up"
echo "== $(date +%T) plain VM (retrieval side)"
VMNAME=plainvm SSH_PORT=2223 NODE_PORT=8082 DATA=images/data-plain.qcow2 setsid nohup ./launch-snpvm.sh plain </dev/null > plainvm.console.log 2>&1 &
for i in $(seq 1 60); do $G2 true 2>/dev/null && break; sleep 5; done; $G2 true || { echo "PLAIN-VM-SSH-FAILED"; exit 1; }
$G2 "sudo sed -i 's|^KBS_URL=.*|KBS_URL=http://10.0.2.2:8801|; s|--llm http://127.0.0.1:8091/v1|--llm http://10.0.2.2:8191/v1|; s|^NODE_ARGS=|NODE_ARGS=--attester mock-insecure |' /etc/attestrag/node.env; sudo systemctl stop llama-chat; sudo systemctl restart attestrag-node; cat /etc/attestrag/node.env | cut -c1-160"
for i in $(seq 1 40); do curl -fs -m 3 http://127.0.0.1:8082/healthz >/dev/null 2>&1 && break; sleep 5; done
echo "plain node healthz: $(curl -s -m 3 http://127.0.0.1:8082/healthz)"; tail -1 kbs2.log | cut -c1-160
$G2 "sudo journalctl -u attestrag-node -n 5 --no-pager -o cat | cut -c1-160"
echo "== query-embedding latency: plain VM CPU vs CVM GPU (5 calls each)"
for i in 1 2 3 4 5; do $G2 "curl -s -o /dev/null -w '%{time_total} ' http://127.0.0.1:8090/v1/embeddings -H 'Content-Type: application/json' -d '{\"input\":\"When was the 2022 Australian Open men final played and who won it?\"}'"; done; echo " <- plain VM (CPU)"
for i in 1 2 3 4 5; do ./g "curl -s -o /dev/null -w '%{time_total} ' http://127.0.0.1:8090/v1/embeddings -H 'Content-Type: application/json' -d '{\"input\":\"When was the 2022 Australian Open men final played and who won it?\"}'"; done; echo " <- CVM (GPU)"
echo "== $(date +%T) RGB through the plain node (generation inside the CVM)"
for ds in en_refine zh_refine; do
  echo "--- $ds"
  venv/bin/python rag_bench.py --node http://127.0.0.1:8082 --policy policies-insecure-baseline.json --insecure-mock --dataset $ds --limit 100 --holdout 0.2 --seed 7 --sweep 1,2,4,8 --skip-ingest --out bench-infonly7b-$ds.json 2>&1 | grep -E "connect=|ask 100/100|concurrency [0-9]+:|rror"
done
echo "INFONLY-DONE $(date +%T)"
