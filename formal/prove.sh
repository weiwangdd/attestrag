#!/bin/bash
# Prove every lemma of both theories. Needs tamarin-prover >= 1.10 and maude 3.x on PATH
# (and MAUDE_LIB pointing at the directory with prelude.maude when maude is unpacked by hand).
# Each lemma runs in its own process with --auto-sources; ~10-60 s each on a 32-core box.
set -u
cd "$(dirname "$0")"
TIMEOUT=${TIMEOUT:-900}
for T in attestrag_release.spthy attestrag_release_gpuid.spthy; do
  echo "== $T"
  for L in $(grep -oE '^lemma [A-Za-z_0-9]+' "$T" | awk '{print $2}'); do
    ( out=$(timeout "$TIMEOUT" tamarin-prover --prove="$L" --auto-sources "$T" 2>&1)
      echo "   $(echo "$out" | grep -E "^\s*$L " | tail -1 | sed 's/^\s*//')" ) &
  done
  wait
done
