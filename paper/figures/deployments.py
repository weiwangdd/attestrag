"""Figure: three deployments of the same pipeline (docs/benchmarks.md, 2026-10-26, 7B generator).

    .venv/bin/python paper/figures/deployments.py   # -> deployments.pdf / .svg / .png

plain VM: nothing protected (mock attestation, GPU in normal mode). inference-only TEE: retrieval in a plain VM,
generation in the confidential VM on the confidential GPU. AttestRAG: the whole pipeline in the confidential VM.
Two panels, one measure each (never a dual axis): answer latency p50 and throughput at 8 users, en and zh.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(__file__).with_suffix("")
DEPLOY = ["plain\nVM", "inference-\nonly TEE", "Attest-\nRAG"]
P50 = {"en": [0.355, 0.46, 0.46], "zh": [0.539, 0.627, 0.623]}      # s
QPS8 = {"en": [4.21, 3.28, 3.55], "zh": [3.36, 2.68, 2.64]}         # answers/s
COLORS = {"en": "#2a78d6", "zh": "#eb6834"}
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#dddcd8"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": MUTED, "pdf.fonttype": 42, "svg.fonttype": "none"})
fig, axes = plt.subplots(1, 2, figsize=(3.33, 2.0), dpi=200)
w = 0.36
for ax, data, title, fmt, ylim in ((axes[0], P50, "answer p50 (s)", "{:.2f}", 0.8), (axes[1], QPS8, "throughput at 8 users\n(answers/s)", "{:.1f}", 5.2)):
    for i, lang in enumerate(("en", "zh")):
        xs = [j + (i - 0.5) * (w + 0.04) for j in range(3)]
        bars = ax.bar(xs, data[lang], width=w, color=COLORS[lang], label=lang, linewidth=0)
        for b, v in zip(bars, data[lang]):
            ax.annotate(fmt.format(v), (b.get_x() + b.get_width() / 2, v), xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=6.2, color=INK)
    ax.set_xticks(range(3)); ax.set_xticklabels(DEPLOY, fontsize=6.5)
    ax.set_ylim(0, ylim); ax.set_title(title, fontsize=7.5, color=INK, pad=4)
    ax.grid(axis="y", color=GRID, linewidth=0.6); ax.set_axisbelow(True); ax.tick_params(axis="y", labelsize=6.5)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
axes[0].legend(frameon=False, fontsize=6.5, loc="upper left", handlelength=1.0)
fig.tight_layout(pad=0.4, w_pad=1.0)
for ext in ("pdf", "svg", "png"):
    fig.savefig(f"{OUT}.{ext}")
print("wrote", OUT.with_suffix(".pdf"))
