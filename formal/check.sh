#!/bin/bash
# Prove every lemma of both theories and compare the verdicts with formal/expected.txt.
# Exit 1 on any mismatch (a lemma that stops being provable, or the v1 attack that stops being found).
# Needs tamarin-prover and maude on PATH (MAUDE_LIB when maude is unpacked by hand); JOBS = parallel lemmas;
# ONLY=<theory file> restricts the run to that theory (CI runs one theory per job). Lines marked local-only
# in expected.txt (the unsigned theory's executable trace: ~15 min and 17 GB) are skipped when CI=true.
set -u
cd "$(dirname "$0")"
export LC_ALL=${LC_ALL:-C.UTF-8}   # tamarin prints U+2200 in lemma statements; a non-UTF-8 locale makes it abort
TIMEOUT=${TIMEOUT:-1200}; JOBS=${JOBS:-4}; ONLY=${ONLY:-}; CI=${CI:-}
tmp=$(mktemp -d); fail=0
want() { [ -z "$ONLY" ] || [ "$1" = "$ONLY" ]; }
runnable() { [ "$1" != local-only ] || [ -z "$CI" ]; }
prove_one() {  # theory lemma
  out=$(timeout "$TIMEOUT" tamarin-prover --prove="$2" --auto-sources "$1" 2>&1)
  echo "$out" | grep -E "^\s*$2 " | tail -1 | sed 's/^\s*//' > "$tmp/$1.$2"
}
export -f prove_one; export TIMEOUT tmp
grep -vE '^#|^\s*$' expected.txt | awk -v only="$ONLY" -v ci="$CI" '(only == "" || $1 == only) && !(ci != "" && $4 == "local-only") {print $1, $2}' | xargs -P "$JOBS" -n 2 bash -c 'prove_one "$0" "$1"'
while read -r theory lemma expected flag; do
  [ -z "$theory" ] && continue; case "$theory" in \#*) continue;; esac
  want "$theory" || continue
  runnable "${flag:-}" || { echo "skip  $theory $lemma: local-only (CI)"; continue; }
  got=$(cat "$tmp/$theory.$lemma" 2>/dev/null)
  if echo "$got" | grep -q "$expected"; then echo "ok    $theory $lemma: $got"
  else echo "FAIL  $theory $lemma: expected '$expected', got '${got:-nothing (timeout?)}'"; fail=1; fi
done < expected.txt
rm -rf "$tmp"
[ $fail = 0 ] && echo "formal: all verdicts as expected${ONLY:+ ($ONLY)}" || echo "formal: MISMATCH"
exit $fail
