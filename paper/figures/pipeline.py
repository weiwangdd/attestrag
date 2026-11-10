#!/usr/bin/env python3
"""Render the paper's Figure 1 (the TikZ pipeline diagram in build.py) on its own, for the README.

    TECTONIC=/path/to/tectonic python3 paper/figures/pipeline.py   # -> pipeline.pdf, pipeline.png

build.py stays the single source of the drawing; this strips the figure environment, compiles it with
the standalone class and rasterises the page with pdftoppm (poppler) at 260 dpi.
"""
import os, re, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
src = (HERE.parent / "build.py").read_text()
body = re.search(r'TIKZ = r"""(.*?)"""', src, re.S).group(1)
for drop in (r"\begin{figure*}[t]\centering", r"\caption{%s}\label{fig:arch}", r"\end{figure*}"):
    body = body.replace(drop, "")
tex = ("\\documentclass[tikz,border=6pt]{standalone}\n\\usetikzlibrary{arrows.meta,positioning,fit,calc}\n"
       "\\begin{document}\n" + body.strip() + "\n\\end{document}\n")
(HERE / "pipeline.tex").write_text(tex)
tectonic = os.environ.get("TECTONIC") or shutil.which("tectonic")
if not tectonic:
    sys.exit("tectonic not found (set TECTONIC)")
subprocess.run([tectonic, "-o", str(HERE), str(HERE / "pipeline.tex")], check=True)
subprocess.run(["pdftoppm", "-r", "260", "-png", "-singlefile", str(HERE / "pipeline.pdf"), str(HERE / "pipeline")], check=True)
(HERE / "pipeline.tex").unlink()
print("wrote", HERE / "pipeline.pdf", HERE / "pipeline.png")
