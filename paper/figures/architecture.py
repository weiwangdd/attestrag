#!/usr/bin/env python3
"""Vector architecture diagram of AttestRAG as deployed on h200 (2026-10-21).

    python3 paper/figures/architecture.py          # -> architecture.svg (+ .png if rsvg-convert exists)

Hand-placed boxes and orthogonal arrows; every element corresponds to a running
component or a call path in the current code (attestrag/, deploy/h200/).
"""

from __future__ import annotations

import html
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).with_suffix(".svg")
FONT = "Helvetica, Arial, 'Liberation Sans', sans-serif"
INK, MUTED, FRAME = "#1c1c1c", "#5a5a5a", "#8a8a8a"
COL = {  # stroke, fill
    "default": ("#444444", "#ffffff"),
    "primary": ("#b3261e", "#fbf1f0"),
    "accent": ("#b26a00", "#fff7e6"),
    "ok": ("#1e7d3a", "#ecf7ee"),
    "muted": ("#8a8a8a", "#f4f4f4"),
}
parts: list[str] = []


def e(s: str) -> str:
    return html.escape(s, quote=True)


def text(x, y, s, size=11, weight="normal", anchor="middle", fill=INK, family=FONT):
    parts.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
                 f'fill="{fill}" font-family="{family}">{e(s)}</text>')


def box(x, y, w, h, title, subs=(), kind="default", title_size=12, sub_size=10, r=6, dashed=False):
    stroke, fill = COL[kind]
    dash = ' stroke-dasharray="6 4"' if dashed else ""
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="1.4"{dash}/>')
    cy = y + 17
    text(x + w / 2, cy, title, title_size, "bold")
    for s in subs:
        cy += sub_size + 4
        text(x + w / 2, cy, s, sub_size, fill=MUTED)


def frame(x, y, w, h, label, color=FRAME):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="none" stroke="{color}" '
                 f'stroke-width="1.2" stroke-dasharray="7 5"/>')
    text(x + 12, y + 17, label, 11, "bold", anchor="start", fill=color)


def arrow(points, label=None, lpos=None, kind="default", both=False, size=10, anchor="middle"):
    stroke = COL[kind][0]
    d = "M " + " L ".join(f"{x},{y}" for x, y in points)
    start = f' marker-start="url(#as-{kind})"' if both else ""
    parts.append(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="1.5" marker-end="url(#ae-{kind})"{start}/>')
    if label:
        lx, ly = lpos
        for i, line in enumerate(label.split("\n")):
            text(lx, ly + i * (size + 2), line, size, fill=MUTED, anchor=anchor)


def markers() -> str:
    out = []
    for k, (stroke, _) in COL.items():
        out.append(f'<marker id="ae-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                   f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{stroke}"/></marker>')
        out.append(f'<marker id="as-{k}" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="7" markerHeight="7" '
                   f'orient="auto"><path d="M10,0 L0,5 L10,10 z" fill="{stroke}"/></marker>')
    return "<defs>" + "".join(out) + "</defs>"


W, H = 1090, 670

# --- frames -----------------------------------------------------------------
frame(20, 20, 1050, 450, "h200 host (untrusted: hypervisor, operator, disk, network)   AMD EPYC 9554, SEV firmware 1.55")
frame(330, 55, 520, 385, "SEV-SNP confidential VM, 32 vCPU + H200 NVL (CC mode) - measured: OVMF + kernel-hashes + dm-verity rootfs", "#7a3030")
frame(330, 535, 400, 130, "customer trust domain", "#1e7d3a")

# --- client ----------------------------------------------------------------------
box(30, 195, 170, 115, "Client SDK / CLI", ["attestrag.sdk", "verify evidence + policy JSON", "(same checks as the KBS)",
                                             "wrap_to(node_pub)", "open_sealed(reply_key)"], kind="primary")

# --- node process ------------------------------------------------------------------
box(350, 95, 200, 310, "attestrag-node :8080", ["one Python process (attestrag.node_server)"], kind="primary", r=8)
box(365, 140, 170, 55, "transport.JsonServer", ["/attestation  /ingest  /query"], sub_size=9.5)
box(365, 205, 170, 68, "Snp + Nvidia attester", ["configfs-tsm report; NVML transcript", "cpu_rd = H(nonce || pk); gpu = H(cpu_rd)"], sub_size=9)
box(365, 283, 170, 55, "ingest + retrieve", ["parse, chunk (800 chars), top-k"], sub_size=9.5)
box(365, 348, 170, 50, "KBSClient", ["ephemeral X25519 key; unwraps DEK"], sub_size=9.5)

# --- services in the VM ---------------------------------------------------------
box(660, 100, 170, 60, "llama-embed :8090", ["Qwen3-Embedding-0.6B Q8_0", "dim 1024; CUDA build, -ngl 99"])
box(660, 190, 170, 60, "Qdrant :6333", ["storage on /run/qdrant (tmpfs)", "= encrypted guest RAM"], kind="accent")
box(660, 280, 170, 60, "llama-chat :8091", ["Qwen2.5-1.5B-Instruct Q4_K_M", "16k KV cache, 4 slots; CUDA build"])
box(660, 374, 170, 58, "H200 NVL, CC mode", ["vfio passthrough, SPDM-protected PCIe,", "bounce buffers; attested via NVML"], kind="primary", sub_size=9)
arrow([(745, 340), (745, 374)], None, None, both=True, kind="muted")
text(752, 361, "CUDA (both servers)", 8.5, fill=MUTED, anchor="start")
arrow([(700, 160), (700, 190)], None, None, both=True, kind="muted")
arrow([(700, 250), (700, 280)], None, None, both=True, kind="muted")

# --- untrusted disk ----------------------------------------------------------------
box(880, 200, 170, 98, "data disk (untrusted)", ["/var/lib/attestrag", "qdrant-attestrag.snapshot.enc", "AES-256-GCM, AAD = collection|dim",
                                              "written after every ingest,", "restored at node start"], kind="muted", sub_size=9.5)

# --- KBS and KDS ----------------------------------------------------------------
box(350, 558, 360, 96, "KBS :8800  (attestrag.kbs_server)", ["today a host process on 127.0.0.1", "SnpVerifier: ARK pin, chain, hwID, SPL, signature, report_data",
                                                              "NvidiaVerifier: NVIDIA root pin, P-384, request nonce, FWID, 64-block digest",
                                                              "policy engine: measurement, min TCB, guest policy, GPU digest  |  keys, audit"],
    kind="ok", sub_size=9.5)
box(30, 560, 170, 62, "AMD KDS", ["VCEK per chip + TCB", "(fetched once, cached on disk)"], kind="muted")

# --- edges -----------------------------------------------------------------------
arrow([(200, 240), (350, 240)], "nonce -> evidence;\nupload and question\nwrapped to node_pub", (275, 205), size=9)
arrow([(350, 268), (200, 268)], "answer sealed with the\none-time reply_key", (275, 285), size=9)
text(275, 311, "HTTP: host :8081 -> guest :8080", 8.5, fill=MUTED)

arrow([(550, 130), (660, 130)], "chunks, query -> vectors", (605, 121), both=True, size=9)
arrow([(550, 220), (660, 220)], "upsert; search top-k", (605, 211), both=True, size=9)
arrow([(550, 310), (660, 310)], "prompt: context +\nquestion", (605, 291), size=9)
text(605, 325, "-> answer", 9, fill=MUTED)
arrow([(830, 250), (880, 250)], None, None, both=True, kind="accent")
text(855, 236, "sealed", 9, fill=MUTED)
text(855, 270, "snapshot", 9, fill=MUTED)

arrow([(495, 405), (495, 560)], "challenge; then (key_id, nonce, pk, evidence)", (503, 492), anchor="start")
arrow([(530, 560), (530, 405)], None, None, kind="ok")
text(538, 508, "DEK wrapped to pk (X25519 + HKDF + AES-GCM),", 10, fill=COL["ok"][0], anchor="start")
text(538, 521, "released only if verification and policy pass", 10, fill=COL["ok"][0], anchor="start")

arrow([(115, 310), (115, 560)], "VCEK", (108, 440), kind="muted", anchor="end")
arrow([(350, 591), (200, 591)], "VCEK", (275, 585), kind="muted")

# --- legend ----------------------------------------------------------------
text(750, 565, "dashed frame = trust boundary; solid box = process or file", 9.5, fill=MUTED, anchor="start")
text(750, 579, "red = attested code;  green = key release;", 9.5, fill=MUTED, anchor="start")
text(750, 593, "orange = plaintext only in encrypted guest RAM;", 9.5, fill=MUTED, anchor="start")
text(750, 607, "grey = untrusted or external", 9.5, fill=MUTED, anchor="start")
text(750, 629, "AttestRAG on h200, state of the code on 2026-10-23", 9.5, fill=MUTED, anchor="start")

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="{FONT}">'
       f'<rect width="{W}" height="{H}" fill="#ffffff"/>' + markers() + "".join(parts) + "</svg>")
OUT.write_text(svg)
print("wrote", OUT)
if shutil.which("rsvg-convert"):
    subprocess.run(["rsvg-convert", "-w", "2180", str(OUT), "-o", str(OUT.with_suffix(".png"))], check=True)
    print("wrote", OUT.with_suffix(".png"))
