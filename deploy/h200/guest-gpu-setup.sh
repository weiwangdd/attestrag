#!/bin/bash
# guest (sudo): NVIDIA open driver 580 + llama.cpp CUDA build into the measured image.
#
# The image stays bootable without a GPU: the llama-* units run through
# /opt/llm/run-llama.sh, which picks the CUDA build when a GPU is visible and the
# CPU build otherwise. With GPU3 of the host passed through in CC mode, the guest
# driver talks to the GPU over an SPDM-protected session and the GPU's attestation
# report can be fetched through NVML (nvidia-ml-py in the attestrag venv).
#
#   g -c guest-gpu-setup.sh /tmp/ && g 'sudo bash /tmp/guest-gpu-setup.sh'
set -euo pipefail
LLM=/opt/llm
LLAMA_TAG=b11753
CUDA_TGZ=llama-${LLAMA_TAG}-bin-ubuntu-cuda-12.8-x64.tar.gz
CUDA_SHA=9aa8ebb82460169db37983a73d6ce1687a68fa127437b5f94cebc6f20075d2ba
CUDART_TGZ=cudart-llama-${LLAMA_TAG}-bin-ubuntu-cuda-12.8-x64.tar.gz
CUDART_SHA=bf58eda480f73682f446d12d820648c3f772687a26a291ffe0af475dca8dd18f
export DEBIAN_FRONTEND=noninteractive

fetch() {  # url dest sha
  if [ -f "$2" ] && echo "$3  $2" | sha256sum -c --status; then echo "ok (cached): $2"; return; fi
  curl -fL --retry 5 --retry-delay 5 -o "$2.part" "$1"
  echo "$3  $2.part" | sha256sum -c --status || { echo "sha256 mismatch: $1" >&2; rm -f "$2.part"; exit 1; }
  mv "$2.part" "$2"; echo "ok: $2"
}

echo "[1/4] NVIDIA open kernel modules + user-space (580, from the Ubuntu archive)"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  linux-modules-nvidia-580-open-$(uname -r) nvidia-kernel-common-580 nvidia-utils-580 \
  libnvidia-compute-580 nvidia-compute-utils-580 libnvidia-cfg1-580 pciutils
# the CC driver path needs the open modules only; make sure nothing pulls the proprietary one
apt-mark hold nvidia-driver-580 2>/dev/null || true
echo "nvidia" > /etc/modules-load.d/nvidia.conf
# bounce buffers for CC DMA: the kernel cmdline carries swiotlb=262144 (see launch-snpvm.sh)

echo "[2/4] llama.cpp CUDA build (same tag as the CPU build) + CUDA runtime libs"
mkdir -p "$LLM/dl" "$LLM/llama-cuda"
fetch "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_TAG/$CUDA_TGZ" "$LLM/dl/$CUDA_TGZ" "$CUDA_SHA"
fetch "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_TAG/$CUDART_TGZ" "$LLM/dl/$CUDART_TGZ" "$CUDART_SHA"
tar -xzf "$LLM/dl/$CUDA_TGZ" -C "$LLM/llama-cuda" --strip-components=1
tar -xzf "$LLM/dl/$CUDART_TGZ" -C "$LLM/llama-cuda" --strip-components=1 2>/dev/null || tar -xzf "$LLM/dl/$CUDART_TGZ" -C "$LLM/llama-cuda"
rm -rf "$LLM/dl"
ls "$LLM/llama-cuda" | head -5

echo "[3/4] runtime selector + units"
cat > "$LLM/run-llama.sh" <<'EOF'
#!/bin/bash
# llama-server launcher: CUDA build if a GPU is present, else the CPU build. Args pass through.
if [ -e /dev/nvidia0 ] || { modprobe nvidia 2>/dev/null && [ -e /dev/nvidia0 ]; }; then
  echo "run-llama: GPU present, using CUDA build (-ngl 99)" >&2
  export LD_LIBRARY_PATH=/opt/llm/llama-cuda
  exec /opt/llm/llama-cuda/llama-server -ngl 99 "$@"
fi
echo "run-llama: no GPU, using CPU build" >&2
export LD_LIBRARY_PATH=/opt/llm/llama
exec /opt/llm/llama/llama-server "$@"
EOF
chmod +x "$LLM/run-llama.sh"
for u in llama-embed llama-chat; do
  sed -i "s#^ExecStart=$LLM/llama/llama-server #ExecStart=$LLM/run-llama.sh #" /etc/systemd/system/$u.service
  grep -q "run-llama.sh" /etc/systemd/system/$u.service || { echo "unit $u not rewritten" >&2; exit 1; }
done
systemctl daemon-reload

echo "[4/4] NVML bindings for the attestrag GPU attester; node attests every CC GPU it finds"
/opt/attestrag/venv/bin/pip install -q nvidia-ml-py
grep -q -- "--gpu auto" /etc/attestrag/node.env || sed -i "s|^NODE_ARGS=|NODE_ARGS=--gpu auto |" /etc/attestrag/node.env
/opt/attestrag/venv/bin/python -c "import pynvml; print('pynvml', pynvml.__file__)"

apt-get clean; rm -rf /var/lib/apt/lists/*
du -sh "$LLM" /opt/attestrag
echo "installed: NVIDIA 580 open modules for $(uname -r), llama.cpp $LLAMA_TAG CUDA 12.8 in $LLM/llama-cuda, run-llama.sh selector"
