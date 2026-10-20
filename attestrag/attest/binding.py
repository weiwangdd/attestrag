"""How a session nonce and a TEE-held public key are bound into report_data.

CPU:  report_data = SHA-384("attestrag-rd-v1" || nonce || tee_pubkey)
GPU:  report_data = SHA-384("attestrag-gpu-bind-v1" || cpu_report_data)

The GPU rule ties every GPU report to the exact CPU report of the same session,
so a verifier can reject GPU evidence replayed from a different CVM/session.
(It does *not* by itself prove the GPU is physically attached to that CVM; see
docs/threat-model.md.)
"""

from __future__ import annotations

from ..common.crypto import sha384

CPU_RD_LABEL = b"attestrag-rd-v1"
GPU_RD_LABEL = b"attestrag-gpu-bind-v1"


def cpu_report_data(nonce: bytes, tee_pubkey: bytes) -> bytes:
    return sha384(CPU_RD_LABEL, nonce, tee_pubkey)


def gpu_report_data(cpu_rd: bytes) -> bytes:
    return sha384(GPU_RD_LABEL, cpu_rd)
