"""Platform-neutral evidence and claims types."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum


class Platform(str, Enum):
    SEV_SNP = "sev-snp"
    TDX = "tdx"
    NVIDIA_CC = "nvidia-cc"  # Hopper/Blackwell GPU confidential computing
    MOCK_CPU = "mock-cpu"
    MOCK_GPU = "mock-gpu"

    @property
    def is_gpu(self) -> bool:
        return self in (Platform.NVIDIA_CC, Platform.MOCK_GPU)


@dataclass(frozen=True)
class Evidence:
    """Raw, signed attestation evidence as produced by a TEE.

    `report` is the platform's native report bytes (for the mock: canonical JSON).
    `cert_chain` carries whatever the verifier needs to anchor the signature to a
    hardware vendor root (VCEK/ASK/ARK for SNP, PCK chain for TDX, ...).
    """

    platform: Platform
    report: bytes
    signature: bytes
    cert_chain: tuple[bytes, ...] = ()

    def to_json(self) -> str:
        return json.dumps(
            {
                "platform": self.platform.value,
                "report": self.report.hex(),
                "signature": self.signature.hex(),
                "cert_chain": [c.hex() for c in self.cert_chain],
            }
        )

    @classmethod
    def from_json(cls, s: str) -> "Evidence":
        d = json.loads(s)
        return cls(
            Platform(d["platform"]),
            bytes.fromhex(d["report"]),
            bytes.fromhex(d["signature"]),
            tuple(bytes.fromhex(c) for c in d["cert_chain"]),
        )


@dataclass(frozen=True)
class CompositeEvidence:
    """CPU CVM evidence plus zero or more GPU evidences bound to it."""

    cpu: Evidence
    gpus: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class Claims:
    """Verified, normalized claims extracted from one piece of evidence.

    Only a Verifier constructs these, after checking signatures; the policy engine
    consumes nothing else.
    """

    platform: Platform
    measurement: str  # hex launch measurement (SNP MEASUREMENT / TDX MRTD+RTMRs digest)
    tcb: dict[str, int]  # component -> security version number
    report_data: bytes
    debug: bool
    issued_at: float
    signer: str = ""  # identity of the hardware root that signed it
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CompositeClaims:
    cpu: Claims
    gpus: tuple[Claims, ...] = ()
