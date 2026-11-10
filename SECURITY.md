# Security policy

attestRAG is a research prototype of confidential RAG on SEV-SNP / TDX / NVIDIA CC hardware. It is
**not production software**: the README's status section lists what is implemented and measured and
what is still a design. Reports are welcome all the same, in particular on the parts that decide
whether a key is released:

- the attestation verifiers (`attestrag/attest/`: SNP, TDX, NVIDIA SPDM/RIM, composite binding),
- the policy engine (`attestrag/policy/`) and the Lean specification it is checked against,
- the key-broker protocol (`attestrag/kbs_client/`, `attestrag/kbs_server.py`) and the Tamarin
  models under `formal/`,
- the node and client protocol (`attestrag/node.py`, `attestrag/sdk/`): envelope encryption,
  tenant authentication, index versioning.

## Reporting

Please report vulnerabilities privately through GitHub's **Report a vulnerability** form on this
repository's Security tab rather than in a public issue. Include the commit, the component, and a
way to reproduce (a synthetic fixture in the style of `tests/` is ideal; never send real keys).

You can expect an acknowledgement within a week. Fixes land on `main` with a test or a formal
lemma that captures the issue, and the report is credited in the commit unless you prefer not.

## Out of scope

- Denial of service against the demo servers (`node_server`, `kbs_server`): they are single-process
  reference implementations without rate limiting or TLS.
- Anything that requires the host already to be inside the trust boundary of the CVM (the threat
  model is in `docs/threat-model.md`).
- The deployment scripts under `deploy/` as such; they document one lab setup.
