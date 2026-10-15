"""Intel TDX attester/verifier (placeholder).

Attester: configfs-tsm (same interface as SNP) yields a TDREPORT -> quote via the
QGS/quote generation service; or /dev/tdx_guest TDX_CMD_GET_REPORT0.

Verifier: verify the DCAP quote (PCK cert chain to the Intel SGX root CA, TCB info
and QE identity from Intel PCS, CRLs), then map MRTD + RTMR[0..3] into
`measurement` and TEE TCB SVN / PCE SVN into `tcb`. TDX-module TCB status
("UpToDate", "OutOfDate", ...) should be surfaced in Claims.extra.
"""

from __future__ import annotations

from .base import Attester, Verifier
from .types import Claims, Evidence


class TdxAttester(Attester):
    def attest(self, report_data: bytes) -> Evidence:
        raise NotImplementedError("TDX attestation requires running inside a TD")


class TdxVerifier(Verifier):
    def verify(self, evidence: Evidence, expected_report_data: bytes) -> Claims:
        raise NotImplementedError("TDX verification not implemented yet")
