"""Key-release policy: verified claims -> allow/deny.

Deliberately a small, total, side-effect-free function over plain data so that it
can later be mirrored by (and checked against) a Lean specification. Every rule
that fails contributes a reason; `allow` holds iff there are no reasons.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..attest.types import Claims, CompositeClaims, Platform


@dataclass(frozen=True)
class Policy:
    allowed_cpu_platforms: frozenset[Platform]
    allowed_measurements: frozenset[str]
    min_tcb: dict[str, int] = field(default_factory=dict)
    allow_debug: bool = False
    max_age_s: float = 300.0
    clock_skew_s: float = 30.0
    require_gpu: bool = False
    allowed_gpu_platforms: frozenset[Platform] = frozenset()
    allowed_gpu_measurements: frozenset[str] = frozenset()  # empty = any
    min_gpu_tcb: dict[str, int] = field(default_factory=dict)
    # NVIDIA services: the verifier records "rim_driver"/"rim_vbios" = ok:<id> | not-found:<id> and "ocsp" = good
    require_gpu_rim: bool = False    # both manifests published, verified and matching
    require_gpu_ocsp: bool = False   # certificate chain checked against NVIDIA's OCSP responder
    # SEV-SNP guest policy (report GUEST_POLICY) allow-list, e.g. {0x30000}; empty = not checked.
    # Covers bits the debug flag alone does not: MIGRATE_MA, SMT, SINGLE_SOCKET, ABI version.
    allowed_guest_policy: frozenset[int] = frozenset()

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(
            allowed_cpu_platforms=frozenset(Platform(p) for p in d["allowed_cpu_platforms"]),
            allowed_measurements=frozenset(m.lower() for m in d["allowed_measurements"]),
            min_tcb={k: int(v) for k, v in d.get("min_tcb", {}).items()},
            allow_debug=bool(d.get("allow_debug", False)),
            max_age_s=float(d.get("max_age_s", 300.0)),
            clock_skew_s=float(d.get("clock_skew_s", 30.0)),
            require_gpu=bool(d.get("require_gpu", False)),
            allowed_gpu_platforms=frozenset(Platform(p) for p in d.get("allowed_gpu_platforms", [])),
            allowed_gpu_measurements=frozenset(m.lower() for m in d.get("allowed_gpu_measurements", [])),
            min_gpu_tcb={k: int(v) for k, v in d.get("min_gpu_tcb", {}).items()},
            require_gpu_rim=bool(d.get("require_gpu_rim", False)),
            require_gpu_ocsp=bool(d.get("require_gpu_ocsp", False)),
            allowed_guest_policy=frozenset(_to_int(p) for p in d.get("allowed_guest_policy", [])),
        )

    @classmethod
    def from_json(cls, s: str) -> "Policy":
        return cls.from_dict(json.loads(s))


def _to_int(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


@dataclass(frozen=True)
class Decision:
    allow: bool
    reasons: tuple[str, ...] = ()


def check_min_tcb(tcb: dict[str, int], minimum: dict[str, int], prefix: str) -> list[str]:
    """Each required component must be present and >= its minimum SVN.

    Component-wise comparison (not lexicographic): SNP/TDX TCBs are vectors and a
    newer value in one component does not compensate for an older one in another.
    """
    out = []
    for comp, need in sorted(minimum.items()):
        have = tcb.get(comp)
        if have is None:
            out.append(f"{prefix}: tcb component '{comp}' missing")
        elif have < need:
            out.append(f"{prefix}: tcb '{comp}'={have} < required {need}")
    return out


def _freshness(c: Claims, policy: Policy, now: float, prefix: str) -> list[str]:
    if c.issued_at > now + policy.clock_skew_s:
        return [f"{prefix}: evidence issued in the future"]
    if now - c.issued_at > policy.max_age_s:
        return [f"{prefix}: evidence older than {policy.max_age_s:.0f}s"]
    return []


def evaluate(policy: Policy, claims: CompositeClaims, now: float) -> Decision:
    reasons: list[str] = []
    cpu = claims.cpu
    if cpu.platform not in policy.allowed_cpu_platforms:
        reasons.append(f"cpu: platform {cpu.platform.value} not allowed")
    if cpu.debug and not policy.allow_debug:
        reasons.append("cpu: debug mode enabled")
    if cpu.measurement.lower() not in policy.allowed_measurements:
        reasons.append("cpu: measurement not in allow-list")
    reasons += check_min_tcb(cpu.tcb, policy.min_tcb, "cpu")
    reasons += _freshness(cpu, policy, now, "cpu")
    if policy.allowed_guest_policy:
        gp = cpu.extra.get("guest_policy")
        if gp is None:
            reasons.append("cpu: guest policy not reported")
        elif _to_int(gp) not in policy.allowed_guest_policy:
            reasons.append(f"cpu: guest policy {gp} not in allow-list")

    if policy.require_gpu and not claims.gpus:
        reasons.append("gpu: GPU evidence required but none presented")
    for i, g in enumerate(claims.gpus):
        p = f"gpu[{i}]"
        if g.platform not in policy.allowed_gpu_platforms:
            reasons.append(f"{p}: platform {g.platform.value} not allowed")
        if g.debug and not policy.allow_debug:
            reasons.append(f"{p}: debug mode enabled")
        if policy.allowed_gpu_measurements and g.measurement.lower() not in policy.allowed_gpu_measurements:
            reasons.append(f"{p}: measurement not in allow-list")
        reasons += check_min_tcb(g.tcb, policy.min_gpu_tcb, p)
        if policy.require_gpu_rim and not all(str(g.extra.get(k, "")).startswith("ok:") for k in ("rim_driver", "rim_vbios")):
            reasons.append(f"{p}: reference manifests not verified "
                           f"(driver {g.extra.get('rim_driver', 'unchecked')}, vbios {g.extra.get('rim_vbios', 'unchecked')})")
        if policy.require_gpu_ocsp and g.extra.get("ocsp") != "good":
            reasons.append(f"{p}: certificate revocation not checked")
        reasons += _freshness(g, policy, now, p)

    return Decision(allow=not reasons, reasons=tuple(reasons))
