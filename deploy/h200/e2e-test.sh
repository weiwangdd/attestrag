#!/bin/bash
# End-to-end test of the h200 SEV-SNP CVM. Runs on the host as a normal user (uses ./g).
#
#   ./e2e-test.sh                 # guest must be running (or AUTO_LAUNCH=1 to start it)
#   POLICY=policy.json ./e2e-test.sh   # use a given policy instead of generating one
#
# Checks: SNP active in the guest, dm-verity root intact and bound to the expected root
# hash, persistent data disk rw, PSP-signed measurement == offline sev-snp-measure value,
# demo passes with the expected policy, demo is denied with a wrong measurement and with
# a too-high minimum TCB.
# Env: SNP=$HOME/snp  MIN_TCB_BL=10 MIN_TCB_TEE=0 MIN_TCB_SNP=24 MIN_TCB_UCODE=88
#      GUEST_POLICY=0x30000  AUTO_LAUNCH=0  BOOT_TIMEOUT=300
set -uo pipefail
SNP=${SNP:-$HOME/snp}
G="$SNP/g"
IMAGES=$SNP/images
PY=/opt/attestrag/venv/bin/python
MIN_TCB_BL=${MIN_TCB_BL:-10}; MIN_TCB_TEE=${MIN_TCB_TEE:-0}; MIN_TCB_SNP=${MIN_TCB_SNP:-24}; MIN_TCB_UCODE=${MIN_TCB_UCODE:-88}
GUEST_POLICY=${GUEST_POLICY:-0x30000}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
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
if [ -n "${POLICY:-}" ]; then cp "$POLICY" "$TMP/good.json"; else mkpolicy "$TMP/good.json" "$EXPECTED" "$MIN_TCB_SNP"; fi
mkpolicy "$TMP/bad-measurement.json" "$(printf '0%.0s' $(seq 1 96))" "$MIN_TCB_SNP"
mkpolicy "$TMP/bad-tcb.json" "$EXPECTED" 99
for f in good bad-measurement bad-tcb; do "$G" -c "$TMP/$f.json" "/tmp/e2e-$f.json" >/dev/null; done

run_demo() { "$G" "sudo $PY -m attestrag.demo --snp --policy /tmp/e2e-$1.json" > "$TMP/out-$1.txt" 2>&1; }

run_demo good
check "demo: KBS releases key to expected measurement" \
  grep -q "KBS released 'index-dek' to measurement ${EXPECTED:0:24}" "$TMP/out-good.txt"
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
  started_kbs=0
  if ! curl -fs "http://127.0.0.1:$KBS_PORT/healthz" >/dev/null 2>&1; then
    nohup "$HOSTPY" -m attestrag.kbs_server --policy "$TMP/good.json" --keys "$SNP/kbs-keys.json" \
      --listen "127.0.0.1:$KBS_PORT" > "$TMP/kbs.log" 2>&1 &
    KBS_PID=$!; started_kbs=1
    for _ in $(seq 1 20); do curl -fs "http://127.0.0.1:$KBS_PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
  fi
  check "KBS reachable on host :$KBS_PORT" curl -fs "http://127.0.0.1:$KBS_PORT/healthz" -o /dev/null
  "$G" "sudo pkill -f '[a]ttestrag.node_server'; sudo rm -rf /var/lib/attestrag/e2e" >/dev/null 2>&1
  "$G" "sudo sh -c 'nohup $PY -m attestrag.node_server --kbs http://10.0.2.2:$KBS_PORT --data-dir /var/lib/attestrag/e2e > /tmp/e2e-node.log 2>&1 &'" >/dev/null 2>&1
  for _ in $(seq 1 60); do curl -fs "http://127.0.0.1:$NODE_PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
  check "node in guest got its key from the KBS and serves host :$NODE_PORT" \
    curl -fs "http://127.0.0.1:$NODE_PORT/healthz" -o /dev/null
  "$G" 'cat /tmp/e2e-node.log' 2>/dev/null | sed 's/^/      node: /' | head -3
  CLI=("$HOSTPY" -m attestrag.sdk --node "http://127.0.0.1:$NODE_PORT")
  check "client: evidence verified against expected policy" \
    bash -c '"$@" verify >/dev/null 2>"$0"' "$TMP/cli.err" "${CLI[@]}" --policy "$TMP/good.json"
  printf 'The VCEK signs SEV-SNP attestation reports.\n\nRisotto needs patience.\n' > "$TMP/doc.txt"
  check "client: encrypted upload accepted" \
    bash -c '"$@" upload "$0" 2>/dev/null | grep -q chunks' "$TMP/doc.txt" "${CLI[@]}" --policy "$TMP/good.json"
  check "client: sealed answer mentions VCEK" \
    bash -c '"$@" ask "What signs SNP reports?" 2>/dev/null | grep -q VCEK' _ "${CLI[@]}" --policy "$TMP/good.json"
  check "index persisted encrypted on the data disk" \
    bash -c "$G 'ls /var/lib/attestrag/e2e/index.enc && ! grep -aq VCEK /var/lib/attestrag/e2e/index.enc'" 
  check "client with wrong measurement policy refuses to send (exit 3)" \
    bash -c '"$@" upload "$0" >/dev/null 2>&1; [ $? = 3 ]' "$TMP/doc.txt" "${CLI[@]}" --policy "$TMP/bad-measurement.json"
  "$G" "sudo pkill -f '[a]ttestrag.node_server'; sudo rm -rf /var/lib/attestrag/e2e /tmp/e2e-node.log" >/dev/null 2>&1
  [ "$started_kbs" = 1 ] && kill "$KBS_PID" 2>/dev/null
else
  echo "SKIP  HTTP flow: attestrag not installed in $HOSTPY (pip install the source tarball into $SNP/venv)"
fi

"$G" 'rm -f /var/lib/attestrag/.e2e /tmp/e2e-*.json' >/dev/null 2>&1
echo "----"
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
