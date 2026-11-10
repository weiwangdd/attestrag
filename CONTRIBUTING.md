# Contributing

Issues and pull requests are welcome. Keep the trust boundary in mind: every change to a verifier,
to the policy engine or to the key-release protocol needs a test that fails without it, and, where a
Tamarin or Lean artefact covers that component, the corresponding lemma.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,nvidia]'
pytest                       # unit + end-to-end tests on recorded hardware evidence (no TEE needed)
```

Optional checks, run by CI as well:

```sh
bash formal/check.sh                                   # Tamarin: verdicts must match formal/expected.txt
(cd formal/lean && lake build AttestRAG attestrag_policy)  # Lean policy spec; tests/test_lean_policy.py diffs it against the engine
```

## Rules of the house

- **No secrets, ever.** Key stores (`kbs-keys.json`), tenant tokens, VM ssh keys and policy files
  with live measurements stay out of the tree. Fixtures contain public evidence only: reports,
  quotes, certificates, SPDM transcripts.
- **Fixtures are real.** Hardware fixtures under `tests/fixtures/` were captured on real machines
  (Genoa SEV-SNP, H200 NVL in CC mode, a GCP C3 TD). Synthetic fixtures are built in code by the test
  helpers (`tests/tdx_fixture.py`, the builders inside `tests/test_nvidia_rim.py`); add new ones
  the same way, and say in the commit where any real evidence came from.
- **Verdicts, not prose.** A verifier change must come with the negative case (what is rejected)
  as well as the positive one.
- **Dependencies.** The runtime depends on `cryptography` and `numpy` only (`faiss`, `signxml` are
  extras); adding a dependency needs a reason in the pull request.
- **Style.** Standard library first, small functions, comments explain why. A failed check is reported as
  `component: what was wrong` (`cpu: measurement not in allow-list`), because that line is what an
  operator sees.

## Licence

Contributions are accepted under the Apache-2.0 licence of the repository (inbound = outbound).
