#!/bin/bash
# End-to-end test of the h200 SEV-SNP CVM. Runs on the host as a normal user (uses ./g).
#
#   ./e2e-test.sh                 # guest must be running (or AUTO_LAUNCH=1 to start it)
#   POLICY=policy.json ./e2e-test.sh   # use a given policy (default: ~/snp/policy-h200.json from relaunch.sh)
#
# Checks: SNP active in the guest, dm-verity root intact and bound to the expected root
# hash, persistent data disk rw, PSP-signed measurement == offline sev-snp-measure value,
# demo passes with the expected policy, demo is denied with a wrong measurement and with
# a too-high minimum TCB; over HTTP: signed key release (an impostor KBS is refused), index
# version commits and rollback refusal, two tenants with tokens isolated from each other.
# Env: SNP=$HOME/snp  MIN_TCB_BL=10 MIN_TCB_TEE=0 MIN_TCB_SNP=24 MIN_TCB_UCODE=88
#      GUEST_POLICY=0x30000  AUTO_LAUNCH=0  BOOT_TIMEOUT=300
set -uo pipefail
SNP=${SNP:-$HOME/snp}
G="$SNP/g"
IMAGES=$SNP/images
PY=/opt/attestrag/venv/bin/python
MIN_TCB_BL=${MIN_TCB_BL:-10}; MIN_TCB_TEE=${MIN_TCB_TEE:-0}; MIN_TCB_SNP=${MIN_TCB_SNP:-24}; MIN_TCB_UCODE=${MIN_TCB_UCODE:-88}
GUEST_POLICY=${GUEST_POLICY:-0x30000}
TMP=$(mktemp -d); [ "${KEEP:-0}" = 1 ] && echo "keeping $TMP" || trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok()   { echo "PASS  $*"; pass=$((pass+1)); }
bad()  { echo "FAIL  $*"; fail=$((fail+1)); }
check(){ local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

EXPECTED=$(cat "$IMAGES/expected-measurement.txt")
ROOTHASH=$(cat "$IMAGES/roothash.txt")
echo "expected measurement: $EXPECTED"
echo "expected root hash:   $ROOTHASH"

# --- 0. guest reachable --------------------------------------------------------------
if ! "$G" true 2>/dev/null; then
  if [ "${AUTO_LAUNCH:-0}" = 1 ]; then
    pgrep -f "[q]emu-system-x86_64 -name snpvm" >/dev/null || \
      (cd "$SNP" && nohup ./launch-snpvm.sh snp </dev/null > snpvm.console.log 2>&1 &)
    for _ in $(seq 1 $(( ${BOOT_TIMEOUT:-300} / 5 ))); do "$G" true 2>/dev/null && break; sleep 5; done
  fi
  "$G" true 2>/dev/null || { echo "guest not reachable (start it: ./launch-snpvm.sh snp)"; exit 2; }
fi
ok "guest reachable over ssh"

# --- 1. platform ---------------------------------------------------------------------
check "SEV-SNP active in guest (dmesg)" \
  bash -c "$G 'sudo dmesg' | grep -q 'Memory Encryption Features active:.*SEV-SNP'"
check "dm-verity root intact (dmsetup status vroot ends with V)" \
  bash -c "$G 'sudo dmsetup status vroot' | grep -qE ' V$'"
check "kernel cmdline roothash == images/roothash.txt" \
  bash -c "$G 'cat /proc/cmdline' | grep -q 'roothash=$ROOTHASH'"
check "cmdline has overlayroot=tmpfs:recurse=0" \
  bash -c "$G 'cat /proc/cmdline' | grep -q 'overlayroot=tmpfs:recurse=0'"
check "root is read-only verity device" \
  bash -c "$G 'findmnt -no SOURCE,OPTIONS /media/root-ro' | grep -qE '^/dev/mapper/vroot .*\bro\b'"

# --- 2. data disk --------------------------------------------------------------------
check "data disk mounted rw at /var/lib/attestrag" \
  bash -c "$G 'findmnt -no SOURCE,OPTIONS /var/lib/attestrag' | grep -qE '^/dev/vd[a-z] .*\brw\b'"
STAMP="e2e-$(date +%s)-$$"
check "data disk writable" \
  bash -c "$G 'echo $STAMP > /var/lib/attestrag/.e2e && sync && cat /var/lib/attestrag/.e2e' | grep -qx '$STAMP'"

# --- 3. measurement: PSP-signed report vs offline value --------------------------------
REPORT=$("$G" "sudo $PY -c '
from attestrag.attest.snp import SnpAttester, SnpReport
r = SnpReport.parse(SnpAttester().attest(b\"e2e\").report)
print(r.measurement.hex(), hex(r.policy), r.version, r.vmpl, int(r.debug))'" 2>/dev/null)
read -r M POL VER VMPL DBG <<<"$REPORT"
echo "report: measurement=$M policy=$POL version=$VER vmpl=$VMPL debug=$DBG"
check "report measurement == expected (sev-snp-measure)" [ "$M" = "$EXPECTED" ]
check "report guest policy == $GUEST_POLICY" [ "$POL" = "$GUEST_POLICY" ]
check "report requested at VMPL0, debug off" [ "$VMPL" = 0 ] && [ "$DBG" = 0 ]

# --- 4. policies ----------------------------------------------------------------------
mkpolicy() {  # $1 out, $2 measurement, $3 min snp
  cat > "$1" <<JSON
{"allowed_cpu_platforms": ["sev-snp"], "allowed_measurements": ["$2"],
 "min_tcb": {"bootloader": $MIN_TCB_BL, "tee": $MIN_TCB_TEE, "snp": $3, "microcode": $MIN_TCB_UCODE},
 "allowed_guest_policy": ["$GUEST_POLICY"]}
JSON
}
# the good policy: POLICY if given, else the one relaunch.sh generates (it carries the GPU fields the
# image's evidence needs), else a CPU-only one from the expected measurement
if [ -n "${POLICY:-}" ]; then cp "$POLICY" "$TMP/good.json"
elif [ -f "$SNP/policy-h200.json" ] && grep -q "\"$EXPECTED\"" "$SNP/policy-h200.json"; then cp "$SNP/policy-h200.json" "$TMP/good.json"; echo "policy: $SNP/policy-h200.json"
else mkpolicy "$TMP/good.json" "$EXPECTED" "$MIN_TCB_SNP"; fi
mkpolicy "$TMP/bad-measurement.json" "$(printf '0%.0s' $(seq 1 96))" "$MIN_TCB_SNP"
mkpolicy "$TMP/bad-tcb.json" "$EXPECTED" 99
# the in-guest demo verifies with an in-process KBS that has no NVIDIA services (no --gpu-rim there), so it gets
# the policy without the OCSP/RIM requirements; the node/client path below runs the full policy
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['require_gpu_ocsp']=False; d['require_gpu_rim']=False; json.dump(d, open(sys.argv[2],'w'))" "$TMP/good.json" "$TMP/demo-good.json"
"$G" -c "$TMP/demo-good.json" "/tmp/e2e-good.json" >/dev/null
for f in bad-measurement bad-tcb; do "$G" -c "$TMP/$f.json" "/tmp/e2e-$f.json" >/dev/null; done

run_demo() { "$G" "sudo $PY -m attestrag.demo --snp --gpu auto --policy /tmp/e2e-$1.json" > "$TMP/out-$1.txt" 2>&1; }

run_demo good
check "demo: KBS releases key to expected measurement" \
  grep -q "KBS released 'index-dek' to measurement ${EXPECTED:0:24}" "$TMP/out-good.txt" || tail -6 "$TMP/out-good.txt" | sed 's/^/      demo: /' | cut -c1-200
check "demo: client verifies node (platform=sev-snp)" grep -q 'client verified node: platform=sev-snp' "$TMP/out-good.txt"
check "demo: answer produced" grep -q '^answer: ' "$TMP/out-good.txt"

denied() {  # $1 name, $2 expected reason substring
  grep -q 'KeyReleaseDenied' "$TMP/out-$1.txt" && grep -q "$2" "$TMP/out-$1.txt" && ! grep -q 'KBS released' "$TMP/out-$1.txt"
}
run_demo bad-measurement
check "demo denied: wrong measurement -> KeyReleaseDenied" denied bad-measurement 'measurement not in allow-list'
run_demo bad-tcb
check "demo denied: min snp TCB 99 -> KeyReleaseDenied" denied bad-tcb "tcb 'snp'=.* < required 99"

# --- 5. three processes over HTTP: KBS on the host, node in the guest, client on the host ---------
HOSTPY=$SNP/venv/bin/python
KBS_PORT=${KBS_PORT:-8800}; NODE_PORT=${NODE_PORT:-8081}
if "$HOSTPY" -c 'import attestrag' 2>/dev/null; then
  # the test needs its two tenants in the KBS and watches its log: it runs its own KBS on the same key store
  # (the production KBS, if one listens on the port, is stopped for the duration and restarted at the end)
  prod_kbs=0
  if curl -fs "http://127.0.0.1:$KBS_PORT/healthz" >/dev/null 2>&1; then
    prod_kbs=1; pkill -f '[a]ttestrag.kbs_server' || true; sleep 1
  fi
  E2E_KEY=e2e-index   # the test node's own key id and version record; the production node keeps index-dek
  # the test's indexes start empty every run, so their version records are reset first (the operator path)
  nohup "$HOSTPY" -m attestrag.kbs_server --policy "$TMP/good.json" --keys "$SNP/kbs-keys.json" --gpu-rim \
    --key-id index-dek --key-id $E2E_KEY --tenant e2e-acme --tenant e2e-globex \
    --reset-version $E2E_KEY --reset-version e2e-acme --reset-version e2e-globex \
    --listen "127.0.0.1:$KBS_PORT" > "$TMP/kbs.log" 2>&1 &
  KBS_PID=$!
  for _ in $(seq 1 20); do curl -fs "http://127.0.0.1:$KBS_PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  check "KBS reachable on host :$KBS_PORT" curl -fs "http://127.0.0.1:$KBS_PORT/healthz" -o /dev/null
  KBS_PUB=$("$HOSTPY" -m attestrag.kbs_server --keys "$SNP/kbs-keys.json" --print-pubkey 2>/dev/null)
  check "KBS identity known (kbs_server --print-pubkey)" [ "${#KBS_PUB}" = 64 ]
  if "$G" 'grep -q -- --kbs-pubkey /etc/attestrag/node.env' 2>/dev/null; then
    check "image pins this KBS identity in node.env (measured)" bash -c "$G 'cat /etc/attestrag/node.env' | grep -q -- \"--kbs-pubkey $KBS_PUB\""
  fi
  PIN="--kbs-pubkey $KBS_PUB"
  # local LLM services (step 3) are optional: use them when present
  LLM_ARGS=""
  if "$G" 'systemctl is-enabled llama-embed.service' >/dev/null 2>&1; then
    check "llama-embed.service active in guest" bash -c "$G 'systemctl is-active llama-embed.service' | grep -qx active"
    check "llama-chat.service active in guest"  bash -c "$G 'systemctl is-active llama-chat.service'  | grep -qx active"
    check "embedding endpoint answers" bash -c "$G 'curl -fs http://127.0.0.1:8090/v1/models' | grep -q embed"
    check "chat endpoint answers"      bash -c "$G 'curl -fs http://127.0.0.1:8091/v1/models' | grep -q chat"
    LLM_ARGS="--embed http://127.0.0.1:8090/v1 --llm http://127.0.0.1:8091/v1 --model chat --embed-model embed"
  fi
  if "$G" 'systemctl is-enabled qdrant.service' >/dev/null 2>&1; then
    check "qdrant.service active in guest" bash -c "$G 'systemctl is-active qdrant.service' | grep -qx active"
    check "qdrant storage is on tmpfs (encrypted RAM), not on a disk" \
      bash -c "$G 'findmnt -no FSTYPE -T /run/qdrant' | grep -qx tmpfs"
    LLM_ARGS="$LLM_ARGS --vector-store qdrant --qdrant-collection e2e"
  fi
  # run a private node for the test (own data dir, same port as the service)
  "$G" "sudo systemctl stop attestrag-node.service 2>/dev/null; sudo pkill -f '[a]ttestrag.node_server'; sudo rm -rf /var/lib/attestrag/e2e" >/dev/null 2>&1
  "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$KBS_PORT --data-dir /var/lib/attestrag/e2e --key-id $E2E_KEY --gpu auto $PIN $LLM_ARGS > /tmp/e2e-node.log 2>&1 &'" >/dev/null 2>&1
  for _ in $(seq 1 120); do curl -fs "http://127.0.0.1:$NODE_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  check "node in guest got its key from the KBS and serves host :$NODE_PORT" \
    curl -fs "http://127.0.0.1:$NODE_PORT/healthz" -o /dev/null || { "$G" 'tail -12 /tmp/e2e-node.log' 2>/dev/null | sed 's/^/      node: /' | cut -c1-220; tail -4 "$TMP/kbs.log" | sed 's/^/      kbs: /' | cut -c1-220; }
  "$G" 'cat /tmp/e2e-node.log' 2>/dev/null | sed 's/^/      node: /' | head -3
  CLI=("$HOSTPY" -m attestrag.sdk --node "http://127.0.0.1:$NODE_PORT" --gpu-rim --tenant "$E2E_KEY")   # the policy requires OCSP
  check "client: evidence verified against expected policy" \
    bash -c '"$@" verify >/dev/null 2>"$0"' "$TMP/cli.err" "${CLI[@]}" --policy "$TMP/good.json"
  printf 'The VCEK signs SEV-SNP attestation reports.\n\nRisotto needs patience.\n' > "$TMP/doc.txt"
  check "client: encrypted upload accepted" \
    bash -c '"$@" upload "$0" 2>/dev/null | grep -q chunks' "$TMP/doc.txt" "${CLI[@]}" --policy "$TMP/good.json"
  "${CLI[@]}" --policy "$TMP/good.json" ask "What signs SNP reports?" > "$TMP/answer.txt" 2>/dev/null
  check "client: sealed answer mentions VCEK" grep -q VCEK "$TMP/answer.txt"
  if [ -n "$LLM_ARGS" ]; then
    check "node used the local embedding model (OpenAIEmbedder)" \
      bash -c "$G 'cat /tmp/e2e-node.log' | grep -q 'embedder=OpenAIEmbedder'"
    check "answer was generated, not the raw chunk" bash -c "! grep -q 'Risotto needs patience' '$TMP/answer.txt'"
    sed 's/^/      answer: /' "$TMP/answer.txt" | head -4
  fi
  check "index persisted encrypted on the data disk" \
    bash -c "$G 'ls /var/lib/attestrag/e2e/*.enc && ! grep -aq VCEK /var/lib/attestrag/e2e/*.enc'"
  if grep -q -- '--vector-store qdrant' <<<"$LLM_ARGS"; then
    check "node used QdrantStore" bash -c "$G 'cat /tmp/e2e-node.log' | grep -q 'vector store=QdrantStore'"
    # reboot-like: drop the live collection, restart the node -> it must restore from the sealed snapshot
    "$G" "curl -fs -X DELETE http://127.0.0.1:6333/collections/e2e >/dev/null; sudo pkill -f '[a]ttestrag.node_server'; sleep 1" >/dev/null 2>&1
    "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$KBS_PORT --data-dir /var/lib/attestrag/e2e --key-id $E2E_KEY --gpu auto $PIN $LLM_ARGS > /tmp/e2e-node2.log 2>&1 &'" >/dev/null 2>&1
    for _ in $(seq 1 120); do curl -fs "http://127.0.0.1:$NODE_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
    check "restarted node restored the collection from the sealed snapshot" \
      bash -c "$G 'cat /tmp/e2e-node2.log' | grep -q '1 chunks at'"
    "${CLI[@]}" --policy "$TMP/good.json" ask "What signs SNP reports?" > "$TMP/answer2.txt" 2>/dev/null
    check "answer after restart still mentions VCEK" grep -q VCEK "$TMP/answer2.txt"
  fi
  check "client with wrong measurement policy refuses to send (exit 3)" \
    bash -c '"$@" upload "$0" >/dev/null 2>&1; [ $? = 3 ]' "$TMP/doc.txt" "${CLI[@]}" --policy "$TMP/bad-measurement.json"

  # --- 6. step-17: signed release, version commits + rollback, tenants -------------------------------------
  stop_node() { "$G" "sudo pkill -f '[a]ttestrag.node_server'" >/dev/null 2>&1; sleep 1; }   # own ssh call: the pattern must not be on the same command line as a node start
  start_node() {  # $1 log name, $2.. extra node args; waits for /healthz (or the node to exit)
    local log=$1; shift
    stop_node
    "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$KBS_PORT --data-dir /var/lib/attestrag/e2e --key-id $E2E_KEY --gpu auto $PIN $LLM_ARGS $* > /tmp/$log 2>&1 &'" >/dev/null 2>&1
    for _ in $(seq 1 120); do
      curl -fs "http://127.0.0.1:$NODE_PORT/healthz" >/dev/null 2>&1 && return 0
      "$G" "pgrep -f '[a]ttestrag.node_server' >/dev/null" 2>/dev/null || return 1
      sleep 1
    done; return 1
  }
  node_log() { "$G" "cat /tmp/$1" 2>/dev/null; }
  export -f node_log; export G
  check "KBS log: commit of version 1 recorded after the first upload" grep -q "commit key=$E2E_KEY version=1" "$TMP/kbs.log"
  # impostor KBS on another port with its own key store: same policy, same evidence, but not the pinned identity
  nohup "$HOSTPY" -m attestrag.kbs_server --policy "$TMP/good.json" --keys "$TMP/impostor-keys.json" --gpu-rim \
    --key-id $E2E_KEY --listen "127.0.0.1:$((KBS_PORT+1))" > "$TMP/impostor.log" 2>&1 &
  IMP_PID=$!
  for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$((KBS_PORT+1))/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  stop_node; "$G" "sudo rm -f /tmp/e2e-imp.log /tmp/e2e-node[3-6].log"
  "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$((KBS_PORT+1)) --data-dir /var/lib/attestrag/e2e-imp --key-id $E2E_KEY --gpu auto $PIN $LLM_ARGS > /tmp/e2e-imp.log 2>&1 &'" >/dev/null 2>&1
  for _ in $(seq 1 60); do "$G" "pgrep -f '[a]ttestrag.node_server' >/dev/null" 2>/dev/null || break; sleep 2; done
  check "node refuses a key release from an impostor KBS (signature not the pinned identity, exit 3)" \
    bash -c "node_log e2e-imp.log | grep -q 'KBS release signature invalid'"
  grep -q 'allowed=True' "$TMP/impostor.log" && echo "      (the impostor KBS did verify the evidence and release a key: only the pin stopped it)"
  kill "$IMP_PID" 2>/dev/null
  # rollback: keep today's snapshot, ingest once more, put the old file back, restart
  start_node e2e-node3.log
  check "restarted node: key release carried the committed index version (1)" bash -c "node_log e2e-node3.log | grep -q 'index version 1 (committed 1)'"
  "$G" "sudo rm -rf /tmp/e2e-yesterday && sudo cp -a /var/lib/attestrag/e2e /tmp/e2e-yesterday"
  printf 'The contract with ACME was cancelled on 2026-10-01.\n' > "$TMP/retract.txt"
  check "client: second upload (index version 2)" \
    bash -c '"$@" upload "$0" 2>/dev/null | grep -q chunks' "$TMP/retract.txt" "${CLI[@]}" --policy "$TMP/good.json"
  check "KBS log: commit of version 2 recorded" grep -q "commit key=$E2E_KEY version=2" "$TMP/kbs.log"
  "$G" "sudo cp -a /tmp/e2e-yesterday/. /var/lib/attestrag/e2e/"
  if start_node e2e-node4.log; then bad "node started on a rolled-back snapshot"; else ok "node refuses to start on the rolled-back snapshot (version 1 < committed 2)"; fi
  check "node log names the rollback" bash -c "node_log e2e-node4.log | grep -q 'index rollback detected: version 1'"
  "$G" "sudo rm -f /var/lib/attestrag/e2e/*.enc"
  if start_node e2e-node5.log; then bad "node started with the snapshot removed"; else ok "node refuses to start with the snapshot removed (committed 2, nothing on disk)"; fi
  # tenants: the KBS issued tokens for e2e-acme and e2e-globex; one node serves both, each with its own index
  "$G" "sudo rm -rf /var/lib/attestrag/e2e-t" >/dev/null 2>&1
  stop_node
  "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$KBS_PORT --data-dir /var/lib/attestrag/e2e-t --gpu auto $PIN $LLM_ARGS --tenant e2e-acme --tenant e2e-globex > /tmp/e2e-node6.log 2>&1 &'" >/dev/null 2>&1
  for _ in $(seq 1 120); do curl -fs "http://127.0.0.1:$NODE_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  check "node serves two tenants, both keys released, client tokens required" \
    bash -c "node_log e2e-node6.log | grep -c \"client token required\" | grep -qx 2"
  ACME=("${CLI[@]}" --policy "$TMP/good.json" --tenant e2e-acme --token-file "$SNP/kbs-keys.e2e-acme.token")
  GLOBEX=("${CLI[@]}" --policy "$TMP/good.json" --tenant e2e-globex --token-file "$SNP/kbs-keys.e2e-globex.token")
  check "tenant acme: upload with its token" bash -c '"$@" upload "$0" 2>/dev/null | grep -q chunks' "$TMP/doc.txt" "${ACME[@]}"
  check "tenant globex: upload with its token" bash -c '"$@" upload "$0" 2>/dev/null | grep -q chunks' "$TMP/retract.txt" "${GLOBEX[@]}"
  "${ACME[@]}" ask "What signs SNP reports?" > "$TMP/acme.txt" 2>"$TMP/acme.err"
  check "tenant acme retrieves its own document" grep -q 'doc.txt' "$TMP/acme.err"
  "${GLOBEX[@]}" ask "What signs SNP reports?" > "$TMP/globex.txt" 2>"$TMP/globex.err"
  check "tenant globex does not see acme's document" bash -c "! grep -q 'doc.txt' '$TMP/globex.err' && grep -q 'retract.txt' '$TMP/globex.err'"
  check "acme's token does not open globex's index (HTTP 403)" \
    bash -c '"$@" ask "x" 2>&1 | grep -q "tenant authentication failed"' _ "${CLI[@]}" --policy "$TMP/good.json" --tenant e2e-globex --token-file "$SNP/kbs-keys.e2e-acme.token"
  check "no token: refused" bash -c '"$@" ask "x" 2>&1 | grep -q "tenant authentication failed"' _ "${CLI[@]}" --policy "$TMP/good.json" --tenant e2e-globex
  check "two sealed indexes on the data disk, one per tenant" bash -c "$G 'ls /var/lib/attestrag/e2e-t/' | grep -c 'e2e-acme\|e2e-globex' | grep -qx 2"
  LOGRM="/tmp/e2e-yesterday /tmp/e2e-node[3-6].log /tmp/e2e-imp.log"; [ "${KEEP:-0}" = 1 ] && LOGRM="/tmp/e2e-yesterday"
  "$G" "sudo rm -rf /var/lib/attestrag/e2e-t /var/lib/attestrag/e2e-imp $LOGRM; curl -fs -X DELETE http://127.0.0.1:6333/collections/e2e-e2e-acme >/dev/null 2>&1; curl -fs -X DELETE http://127.0.0.1:6333/collections/e2e-e2e-globex >/dev/null 2>&1" >/dev/null 2>&1
  LOGRM="/tmp/e2e-node.log /tmp/e2e-node2.log"; [ "${KEEP:-0}" = 1 ] && LOGRM=""
  "$G" "sudo pkill -f '[a]ttestrag.node_server'; sudo rm -rf /var/lib/attestrag/e2e $LOGRM; curl -fs -X DELETE http://127.0.0.1:6333/collections/e2e >/dev/null 2>&1; sudo systemctl start attestrag-node.service 2>/dev/null" >/dev/null 2>&1
  kill "$KBS_PID" 2>/dev/null; sleep 1
  if [ "$prod_kbs" = 1 ]; then   # the production KBS as relaunch.sh starts it; setsid: not a child this script waits on
    setsid nohup "$SNP/venv/bin/python" -m attestrag.kbs_server --policy "$SNP/policy-h200.json" --keys "$SNP/kbs-keys.json" \
       --listen "127.0.0.1:$KBS_PORT" --gpu-rim >> "$SNP/kbs.log" 2>&1 < /dev/null &
    sleep 2; curl -fs "http://127.0.0.1:$KBS_PORT/healthz" >/dev/null && echo "      production KBS restarted on :$KBS_PORT"
  fi
else
  echo "SKIP  HTTP flow: attestrag not installed in $HOSTPY (pip install the source tarball into $SNP/venv)"
fi

"$G" 'rm -f /var/lib/attestrag/.e2e /tmp/e2e-*.json' >/dev/null 2>&1
echo "----"
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
