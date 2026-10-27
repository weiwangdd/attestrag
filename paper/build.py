#!/usr/bin/env python3
"""Build the USENIX-format PDF of the paper from attestrag.md.

    python3 paper/build.py            # -> paper/usenix/attestrag.pdf

Needs pandoc and a LaTeX engine (TECTONIC=/path/to/tectonic, or pdflatex+bibtex on PATH).
attestrag.md stays the single source: this script rewrites tables, the figure, the
formulas and the [n] citations into LaTeX, converts the prose with pandoc and wraps it
in the USENIX template (usenix2019_v3.sty) with refs.bib.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "attestrag.md"
OUT = HERE / "usenix"

# [n] in attestrag.md -> BibTeX keys in refs.bib
CITE = {
    1: "chrapek2025confidential", 2: "schambach2026enclavex", 3: "asad2026blackwell",
    4: "tan2025pipellm", 5: "ibarra2025ccgpu", 6: "gputravel2025", 7: "chuang2025teefail",
    8: "demeulemeester2026batteringram", 9: "shen2026aspbreaker",
    10: "schlueter2026fabricked,zhang2026stackwarp,schlueter2026staleus",
    11: "schlueter2025heracles", 12: "gu2025nvidiacc", 13: "cheng2025remoterag", 14: "zhou2025sag",
    15: "chen2025algen", 16: "mu2026securerag", 17: "palanisamy2026ragsp", 18: "chen2024rgb",
    19: "rfc9334", 20: "amd2024snpabi", 21: "nvidia2024cc", 22: "trustee", 23: "llamacpp",
    24: "qdrant", 25: "sevsnpmeasure",
}

TABLES = [  # in order of appearance: (float env, column spec, label, caption, lead sentence)
    ("table", "p{1.55in}ll", "tab:quality",
     "Retrieval and answer quality on RGB inside the SEV-SNP VM (100 questions per language: 80 answerable, 20 held out; k = 4).",
     "`Table~\\ref{tab:quality}`{=latex} shows the results."),
    ("table", "p{1.45in}ll", "tab:latency",
     "Single-user latency measured at the client, including the network hop into the guest.",
     "`Table~\\ref{tab:latency}`{=latex} gives the single-user latencies."),
    ("table*", "lrlrlr", "tab:sweep",
     "Concurrency sweep: $N$ clients, each with its own attested session, 16 unseen questions per level.",
     "`Table~\\ref{tab:sweep}`{=latex} shows the sweep."),
    ("table", "p{1.6in}p{0.95in}p{0.95in}", "tab:gpu",
     "The confidential GPU configuration: same image and corpus, H200 NVL in CC mode attached to the VM, both llama.cpp servers on CUDA.",
     "`Table~\\ref{tab:gpu}`{=latex} gives the numbers."),
    ("table*", "p{1.25in}p{1.3in}p{1.3in}p{1.3in}p{1.4in}", "tab:model",
     "Model size on the confidential GPU: Qwen2.5-1.5B, 7B, 14B and the Qwen3-Next-80B mixture of experts (all Q4\\_K\\_M), the last two with the 8B embedder; same image family, corpus and questions.",
     "`Table~\\ref{tab:model}`{=latex} compares the two generators."),
    ("table", "p{1.1in}p{0.6in}p{0.75in}p{0.65in}", "tab:cost",
     "The pipeline in an ordinary VM, with only generation in the confidential VM, and entirely in the confidential VM (7B generator, same image, corpus and questions).",
     ""),
    ("table*", "p{1.2in}p{1.5in}p{1.5in}p{1.5in}p{1.5in}", "tab:scale",
     "Confidential against plain, per generator, on one image: inference-server token rates (CVM vs plain VM, ratio) and the end-to-end overhead at one and eight users.",
     ""),
    ("table*", "p{2.6in}p{1.3in}p{2.45in}", "tab:status",
     "Status of each claim in this draft.", "`Table~\\ref{tab:status}`{=latex} lists every claim with its status."),
]

TEX_SPECIALS = {"&": r"\&", "%": r"\%", "#": r"\#", "_": r"\_", "$": r"\$"}


def esc(s: str) -> str:
    s = "".join(TEX_SPECIALS.get(c, c) for c in s)
    s = re.sub(r"\*\*(.+?)\*\*", r"\\textbf{\1}", s)
    s = re.sub(r"`(.+?)`", r"\\texttt{\1}", s)
    return s.replace("→", r"$\rightarrow$").replace("–", "--")


def table_to_tex(rows: list[list[str]], spec) -> str:
    env, cols, label, caption, lead = spec
    head, body = rows[0], rows[2:]
    lines = [lead, "", "```{=latex}", f"\\begin{{{env}}}[t]\\centering\\small\\setlength{{\\tabcolsep}}{{4pt}}",
             f"\\begin{{tabular}}{{{cols}}}\\toprule",
             " & ".join(f"\\textbf{{{esc(c)}}}" if c else "" for c in head) + r" \\ \midrule"]
    lines += [" & ".join(esc(c) for c in r) + r" \\" for r in body]
    lines += ["\\bottomrule\\end{tabular}", f"\\caption{{{caption}}}\\label{{{label}}}", f"\\end{{{env}}}", "```", ""]
    return "\n".join(lines)


def convert_tables(text: str) -> str:
    out, buf, i = [], [], 0
    lines = text.split("\n")
    for ln in lines + [""]:
        if ln.startswith("|"):
            buf.append([c.strip() for c in ln.strip().strip("|").split("|")])
            continue
        if buf:
            out.append(table_to_tex(buf, TABLES[i]))
            i += 1
            buf = []
        out.append(ln)
    assert i == len(TABLES), f"expected {len(TABLES)} tables, found {i}"
    return "\n".join(out)


TIKZ = r"""\begin{figure*}[t]\centering
\begin{tikzpicture}[font=\small, node distance=4mm,
  stage/.style={draw, rounded corners=2pt, minimum width=3.9cm, minimum height=6mm, align=center, fill=white},
  gpu/.style={draw, rounded corners=2pt, minimum width=3.9cm, minimum height=6mm, align=center, fill=green!6},
  vm/.style={draw, dashed, rounded corners=4pt, inner sep=3mm},
  arr/.style={-{Stealth[length=2mm]}, thick}, lbl/.style={font=\scriptsize, fill=white, inner sep=1pt}]
  \node[stage] (ingest) {ingest and parse};
  \node[stage, below=of ingest] (embed) {embedding (llama.cpp, CUDA)};
  \node[stage, below=of embed] (index) {vector index (Qdrant on tmpfs)};
  \node[stage, below=of index] (retrieve) {retrieve and filter};
  \node[stage, below=of retrieve] (gen) {generate (llama.cpp, CUDA)};
  \node[gpu, right=10mm of index, text width=3.6cm, minimum height=22mm]
    (gpunode) {\textbf{H200 in CC mode}\\[1pt] \scriptsize passed through to this VM; SPDM-protected PCIe, bounce buffers; attestation transcript via NVML};
  \node[vm, fit=(ingest)(gen)(gpunode), label={[font=\small\bfseries]above:confidential VM (SEV-SNP; TDX \textbf{[design]})}] (cvm) {};
  \node[stage, left=14mm of index, text width=3.2cm, minimum height=22mm, align=left]
    (client) {\textbf{client SDK}\\[1pt] 1. verify composite evidence against the policy\\ 2. upload, encrypted to the node key\\ 3. open the sealed answer};
  \node[stage, fill=blue!5, minimum width=9.5cm, minimum height=9mm, below=12mm of gen, align=center]
    (kbs) {\textbf{KBS + policy engine} (customer's trust domain)\\ \scriptsize releases the index key only if the SNP report and the GPU transcript are bound to this session and the measurements, TCB and guest policy pass};
  \draw[arr, <->] (embed.east) -- (gpunode.west |- embed.east) node[lbl, midway, above] {CUDA};
  \draw[arr, <->] (gen.east) -- (gpunode.west |- gen.east) node[lbl, midway, above] {CUDA};
  \draw[arr] (client.north) |- (ingest.west) node[lbl, pos=0.8] {upload (encrypted)};
  \draw[arr] (retrieve.west) -- (client.east |- retrieve.west) node[lbl, midway, above] {sealed answer};
  \draw[arr, <->] (cvm.south) -- (kbs.north -| cvm.south) node[lbl, midway] {prove (SNP report + GPU transcript), get key};
  \draw[arr, <->] (client.south) |- ([yshift=2mm]kbs.west) node[lbl, pos=0.25, anchor=east, xshift=-1mm] {verify};
\end{tikzpicture}
\caption{%s}\label{fig:arch}
\end{figure*}
"""


def convert_figure(text: str) -> str:
    m = re.search(r"```\n(  client SDK.*?)```\n\n\*Figure 1\. (.*?)\*\n", text, re.S)
    assert m, "figure block not found"
    fig = "```{=latex}\n" + TIKZ % esc(m.group(2)) + "```\n"
    text = text[:m.start()] + fig + text[m.end():]
    return text.replace("The CPU confidential VM runs the ingest parser",
                        "`Figure~\\ref{fig:arch}`{=latex} shows the architecture. The CPU confidential VM runs the ingest parser", 1)


FORMULA = r"""```{=latex}
\begin{footnotesize}
\begin{align*}
\mathit{rd}_{\mathrm{cpu}} &= \mathrm{SHA\text{-}384}(\ell_{\mathrm{cpu}} \parallel \mathit{nonce} \parallel \mathit{pk}_{\mathrm{tee}} \parallel \mathit{id}_{\mathrm{gpu},1} \parallel \cdots \parallel \mathit{id}_{\mathrm{gpu},n})\\
\mathit{rd}_{\mathrm{gpu}} &= \mathrm{SHA\text{-}384}(\ell_{\mathrm{gpu}} \parallel \mathit{rd}_{\mathrm{cpu}})
\end{align*}
\end{footnotesize}
```

with the labels $\ell_{\mathrm{cpu}}$ = `attestrag-rd-v2`, $\ell_{\mathrm{gpu}}$ = `attestrag-gpu-bind-v1` and """


def convert_formula(text: str) -> str:
    m = re.search(r"```\ncpu_report_data = .*?```\n\nwith ", text, re.S)
    assert m, "formula block not found"
    return text[:m.start()] + FORMULA + text[m.end():]


def convert_cites(text: str) -> str:
    def rep(m):
        nums = [int(x) for x in m.group(1).split(",")]
        return "`\\cite{" + ",".join(CITE[n] for n in nums) + "}`{=latex}"
    return re.sub(r"\[(\d+(?:,\s*\d+)*)\]", rep, text)


def preprocess(md: str) -> tuple[str, str, str]:
    lines = md.split("\n")
    title = lines[0].lstrip("# ").strip()
    note = lines[2].strip().strip("*")
    body = "\n".join(lines[3:])
    # drop the markdown reference list (BibTeX replaces it)
    body = re.sub(r"\n## References\n.*?(?=\n## Appendix)", "\n", body, flags=re.S)
    body = body.replace("## Appendix A: claim status", "```{=latex}\n\\appendix\n```\n\n## Claim status")
    body = body.replace("## Abstract\n", "```{=latex}\n\\begin{abstract}\n```\n", 1)
    body = body.replace("\n## 1 Introduction", "\n```{=latex}\n\\end{abstract}\n```\n\n## 1 Introduction", 1)
    body = re.sub(r"^(##+) \d+(?:\.\d+)? ", r"\1 ", body, flags=re.M)  # LaTeX numbers sections
    body = convert_figure(body)
    body = convert_formula(body)
    body = convert_tables(body)
    body = convert_cites(body)
    body = body.replace("→", "`$\\rightarrow$`{=latex}").replace("…", "\\ldots{}")
    return title, note, body


TEMPLATE = r"""\documentclass[letterpaper,twocolumn,10pt]{article}
\usepackage{usenix2019_v3}
\usepackage{amsmath}
\usepackage{booktabs}
\usepackage{textcomp}
\usepackage{xurl}
\usepackage{graphicx}
\usepackage{tikz}
\usetikzlibrary{positioning,arrows.meta,fit}
\providecommand{\tightlist}{\setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}}
\begin{document}
\date{}
\title{\Large \bf %(title)s}
\author{{\rm Wei Wang}\\ \emph{affiliation to be added}}
\maketitle
{\small\noindent\emph{%(note)s}}
%(body)s
\bibliographystyle{plain}
\bibliography{refs}
\end{document}
"""


def main() -> None:
    title, note, body_md = preprocess(SRC.read_text())
    OUT.mkdir(exist_ok=True)
    (OUT / "body.md").write_text(body_md.replace("figures/architecture.svg", "figures/architecture.pdf"))
    body = subprocess.run(["pandoc", "-f", "markdown-smart", "-t", "latex", "--wrap=none", "--shift-heading-level-by=-1", str(OUT / "body.md")],
                          check=True, capture_output=True, text=True).stdout
    m = re.search(r"\\begin\{figure\}\n\\centering\n[^\n]*architecture\.pdf[^\n]*\n(\\caption\{.*?\})\n\\end\{figure\}", body, re.S)
    assert m, "architecture figure not found in pandoc output"
    body = body[:m.start()] + ("\\begin{figure*}[t]\n\\centering\n\\includegraphics[width=\\textwidth]{figures/architecture.pdf}\n"
                               + m.group(1) + "\\label{fig:impl}\n\\end{figure*}") + body[m.end():]
    shutil.copytree(HERE / "figures", OUT / "figures", dirs_exist_ok=True)
    tex = TEMPLATE % {"title": esc(title), "note": esc(note), "body": body}
    (OUT / "attestrag.tex").write_text(tex)
    for f in ("refs.bib", "usenix2019_v3.sty"):
        if not (OUT / f).exists():
            shutil.copy(HERE / f, OUT / f)
    tectonic = os.environ.get("TECTONIC") or shutil.which("tectonic")
    if tectonic:
        subprocess.run([tectonic, "--keep-logs", "-o", str(OUT), str(OUT / "attestrag.tex")], check=True)
    else:
        for cmd in (["pdflatex", "-interaction=nonstopmode", "attestrag"], ["bibtex", "attestrag"],
                    ["pdflatex", "-interaction=nonstopmode", "attestrag"], ["pdflatex", "-interaction=nonstopmode", "attestrag"]):
            subprocess.run(cmd, cwd=OUT, check=True, capture_output=True)
    print("wrote", OUT / "attestrag.pdf")


if __name__ == "__main__":
    sys.exit(main())
