"""AMD SEV-SNP attester/verifier (placeholder).

Attester (inside the CVM), Linux >= 6.7:
  configfs-tsm: mkdir /sys/kernel/config/tsm/report/<x>; write 64-byte report_data
  to inblob; read outblob (1184-byte ATTESTATION_REPORT) and auxblob (certs).
  Fallback: SNP_GET_REPORT ioctl on /dev/sev-guest.

Verifier:
  1. Fetch VCEK for (chip_id, reported_tcb) from AMD KDS (or use the VLEK / cached
     certs in auxblob); verify VCEK <- ASK <- ARK, with ARK pinned per product
     (Milan / Genoa / Turin).
  2. Verify ECDSA-P384 signature over report[0x0:0x2A0].
  3. Check report_data, VMPL, policy.DEBUG == 0, and extract MEASUREMENT,
     REPORTED_TCB {bootloader, tee, snp, microcode} (and FMC on Turin) into Claims.
Libraries worth evaluating: virtee/sev (Rust), go-sev-guest, Trustee attestation-service.
"""

from __future__ import annotations

from .base import Attester, Verifier
from .types import Claims, Evidence


class SnpAttester(Attester):
    def attest(self, report_data: bytes) -> Evidence:
        raise NotImplementedError("SEV-SNP attestation requires running inside an SNP guest")


class SnpVerifier(Verifier):
    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        raise NotImplementedError("SEV-SNP verification not implemented yet")
