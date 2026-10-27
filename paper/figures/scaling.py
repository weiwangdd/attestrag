"""Figure: confidential-computing overhead against generator size (docs/benchmarks.md, 2026-10-27).

    .venv/bin/python paper/figures/scaling.py   # -> scaling.pdf / .svg / .png (matplotlib, dev-only dependency)

Numbers are the CVM-vs-plain-VM pairs of deploy/h200/scale-experiment.sh: token rates from the inference
server's own timings (prompt cache off), answer latency and 8-user throughput from RGB through the attested
client; en and zh averaged for the two end-to-end series. Overhead = extra time for latency, lost rate for
token rates and throughput (1 - CVM/plain), so every series reads "what confidential mode costs".
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = Path(__file__).with_suffix("")
MODELS = ["1.5B", "7B", "14B", "80B-A3B\n(MoE)"]
# (cvm, plain) measurements, see docs/benchmarks.md "Does the confidential-computing overhead grow with the model?"
PREFILL = [(21623, 25246), (7946, 8822), (4068, 4347), (3262, 3593)]          # tokens/s, c=1
DECODE = [(360, 453), (196, 220), (112, 120), (153, 174)]                      # tokens/s, c=1
ANSWER_EN = [(0.17, 0.13), (0.45, 0.39), (0.81, 0.74), (1.34, 1.14)]           # ask p50, s
ANSWER_ZH = [(0.25, 0.19), (0.63, 0.55), (1.19, 1.03), (1.72, 1.53)]
QPS8_EN = [(8.06, 11.35), (3.29, 3.95), (1.43, 1.71), (0.65, 0.89)]            # 8 users, answers/s
QPS8_ZH = [(5.99, 8.87), (2.67, 3.25), (1.23, 1.54), (0.73, 0.96)]
lost = lambda pairs: [100 * (1 - c / p) for c, p in pairs]                     # noqa: E731
extra = lambda pairs: [100 * (c / p - 1) for c, p in pairs]                    # noqa: E731
avg = lambda a, b: [(x + y) / 2 for x, y in zip(a, b)]                         # noqa: E731
SERIES = [  # fixed categorical order (reference palette slots 1-4)
    ("answer p50 (RGB, en/zh mean)", avg(extra(ANSWER_EN), extra(ANSWER_ZH)), "#2a78d6", "o"),
    ("8-user throughput (RGB, en/zh mean)", avg(lost(QPS8_EN), lost(QPS8_ZH)), "#eb6834", "s"),
    ("decode rate (server)", lost(DECODE), "#1baf7a", "^"),
    ("prefill rate (server)", lost(PREFILL), "#eda100", "D"),
]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#dddcd8"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                     "xtick.color": INK, "ytick.color": INK, "pdf.fonttype": 42, "svg.fonttype": "none"})
fig, ax = plt.subplots(figsize=(3.33, 2.7), dpi=200)
x = list(range(len(MODELS)))
def spread(vals, gap=2.6):
    """nudge label y-positions apart so that end labels never collide"""
    order = sorted(range(len(vals)), key=lambda i: vals[i]); out = list(vals)
    for a, b in zip(order, order[1:]):
        if out[b] - out[a] < gap: out[b] = out[a] + gap
    return out
first = spread([ys[0] for _, ys, _, _ in SERIES]); last = spread([ys[-1] for _, ys, _, _ in SERIES])
for k, (name, ys, color, marker) in enumerate(SERIES):
    ax.plot(x, ys, color=color, marker=marker, markersize=4.5, linewidth=1.6, label=name, markeredgecolor="white", markeredgewidth=0.6)
    ax.annotate(f"{ys[0]:.0f}%", (x[0] - 0.08, first[k]), ha="right", va="center", fontsize=6.3, color=INK)
    ax.annotate(f"{ys[-1]:.0f}%", (x[-1] + 0.08, last[k]), ha="left", va="center", fontsize=6.3, color=INK)
ax.set_xticks(x); ax.set_xticklabels(MODELS); ax.set_xlim(-0.6, len(MODELS) - 0.4)
ax.set_ylim(0, 36); ax.set_yticks([0, 10, 20, 30]); ax.set_yticklabels(["0", "10", "20", "30 %"])
ax.set_ylabel("overhead of confidential mode", color=INK, fontsize=7.5)
ax.set_xlabel("")
ax.grid(axis="y", color=GRID, linewidth=0.6); ax.set_axisbelow(True)
for s in ("top", "right"): ax.spines[s].set_visible(False)
ax.legend(frameon=False, fontsize=6.2, loc="upper center", ncol=2, handlelength=1.5, labelspacing=0.3, columnspacing=1.2, bbox_to_anchor=(0.45, -0.16))
fig.tight_layout(pad=0.4)
for ext in ("pdf", "svg", "png"):
    fig.savefig(f"{OUT}.{ext}")
print("wrote", OUT.with_suffix(".pdf"))
