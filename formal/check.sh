#!/bin/bash
# Prove every lemma of both theories and compare the verdicts with formal/expected.txt.
# Exit 1 on any mismatch (a lemma that stops being provable, or the v1 attack that stops being found).
# Needs tamarin-prover and maude on PATH (MAUDE_LIB when maude is unpacked by hand); JOBS = parallel lemmas.
set -u
cd "$(dirname "$0")"
TIMEOUT=${TIMEOUT:-1200}; JOBS=${JOBS:-4}
tmp=$(mktemp -d); fail=0
prove_one() {  # theory lemma
  out=$(timeout "$TIMEOUT" tamarin-prover --prove="$2" --auto-sources "$1" 2>&1)
  echo "$out" | grep -E "^\s*$2 " | tail -1 | sed 's/^\s*//' > "$tmp/$1.$2"
}
export -f prove_one; export TIMEOUT tmp
grep -vE '^#|^\s*$' expected.txt | awk '{print $1, $2}' | xargs -P "$JOBS" -n 2 bash -c 'prove_one "$0" "$1"'
while read -r theory lemma expected; do
  [ -z "$theory" ] && continue; case "$theory" in \#*) continue;; esac
  got=$(cat "$tmp/$theory.$lemma" 2>/dev/null)
  if echo "$got" | grep -q "$expected"; then echo "ok    $theory $lemma: $got"
  else echo "FAIL  $theory $lemma: expected '$expected', got '${got:-nothing (timeout?)}'"; fail=1; fi
done < expected.txt
rm -rf "$tmp"
[ $fail = 0 ] && echo "formal: all verdicts as expected" || echo "formal: MISMATCH"
exit $fail
