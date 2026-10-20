#!/usr/bin/env bash
# Create .venv with Python 3.11 without touching the system: uv is installed into
# a throwaway venv and the Python toolchain is kept under ./.python.
set -euo pipefail
cd "$(dirname "$0")/.."
export UV_PYTHON_INSTALL_DIR="$PWD/.python" UV_CACHE_DIR="$PWD/.uv-cache"
[ -x .bootstrap/bin/uv ] || { python3 -m venv .bootstrap && .bootstrap/bin/pip install -q uv; }
.bootstrap/bin/uv python install 3.11
[ -x .venv/bin/python ] || .bootstrap/bin/uv venv --python 3.11 .venv
.bootstrap/bin/uv pip install --python .venv/bin/python -e ".[dev]"
echo "ok: .venv/bin/python -m pytest -q"
