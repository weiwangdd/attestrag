"""How a session nonce, a TEE-held public key and the attached GPUs are bound into report_data.

CPU:  report_data = SHA-384("attestrag-rd-v2" || nonce || tee_pubkey || gpu_id_1 || ... || gpu_id_n)
GPU:  report_data = SHA-384("attestrag-gpu-bind-v1" || cpu_report_data)

gpu_id_i is the identity of the i-th attached GPU as the TEE's own driver sees it (for NVIDIA the
SHA-384 of its attestation-key certificate; see attest.base.gpu_identity), sorted, so that the CPU
report commits to *which* GPUs attested for this session. The GPU rule ties every GPU report to
the exact CPU report of the same session (no replay from another session); the identity inside
the CPU report ties the session to the GPU the TEE is actually talking to (no substitution by
another certified GPU in transit). The second rule is the one-line change the Tamarin model in
formal/ asked for: without it an operator with a confidential GPU of its own could swap the GPU
half of the evidence. Without GPUs the formula degrades to SHA-384(label || nonce || pk).
"""

from __future__ import annotations

from typing import Iterable

from ..common.crypto import sha384

CPU_RD_LABEL = b"attestrag-rd-v2"
GPU_RD_LABEL = b"attestrag-gpu-bind-v1"


def cpu_report_data(nonce: bytes, tee_pubkey: bytes, gpu_ids: Iterable[bytes] = ()) -> bytes:
    return sha384(CPU_RD_LABEL, nonce, tee_pubkey, *sorted(gpu_ids))


def gpu_report_data(cpu_rd: bytes) -> bytes:
    return sha384(GPU_RD_LABEL, cpu_rd)
