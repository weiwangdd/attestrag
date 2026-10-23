#!/bin/bash
# Run inside the guest (sudo) while the golden image is booted writable (VERITY=0), after
# guest-attestrag-setup.sh: install llama.cpp + two GGUF models under /opt/llm and systemd
# units so the CVM boots straight into "attest -> get key -> serve":
#
#   llama-embed.service   llama-server --embedding, Qwen3-Embedding-0.6B Q8_0, 127.0.0.1:8090
#   llama-chat.service    llama-server, Qwen2.5-7B-Instruct Q4_K_M (CHAT_MODEL=1.5b for the small one), 127.0.0.1:8091
#   attestrag-node.service node_server --embed/--llm -> the two above, KBS from /etc/attestrag/node.env
#
# Everything is pinned by sha256 and ends up inside the dm-verity measured image.
set -euo pipefail
LLM=/opt/llm
LLAMA_TAG=${LLAMA_TAG:-b11753}
LLAMA_URL=https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_TAG/llama-$LLAMA_TAG-bin-ubuntu-x64.tar.gz
LLAMA_SHA=${LLAMA_SHA:-af40d3acec2ebae7ca3c26cdfa012d4cb6d4ae598aa668194d27c5252a435b62}
EMBED_FILE=Qwen3-Embedding-0.6B-Q8_0.gguf
EMBED_URL=https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/main/$EMBED_FILE
EMBED_SHA=06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439
# generator: Qwen2.5-7B-Instruct Q4_K_M (official GGUF, two shards; llama-server loads both from the first)
# or, with CHAT_MODEL=1.5b, the 1.5B model of the CPU-only baseline. Both files stay in the image.
CHAT_MODEL=${CHAT_MODEL:-7b}
SMALL_FILE=qwen2.5-1.5b-instruct-q4_k_m.gguf
SMALL_URL=https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/$SMALL_FILE
SMALL_SHA=6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
BIG_FILE=qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf
BIG_FILE2=qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf
BIG_URL=https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main
BIG_SHA=dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db
BIG_SHA2=539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a
case "$CHAT_MODEL" in
  7b)   CHAT_FILE=$BIG_FILE;   CHAT_NAME="Qwen2.5-7B-Instruct" ;;
  1.5b) CHAT_FILE=$SMALL_FILE; CHAT_NAME="Qwen2.5-1.5B-Instruct" ;;
  *) echo "CHAT_MODEL must be 7b or 1.5b" >&2; exit 1 ;;
esac
KBS_URL=${KBS_URL:-http://10.0.2.2:8800}
# chat: 4 slots sharing a 16k unified KV cache (b11753 defaults to 4 slots; with -c 4096 two
# concurrent ~2k-token RAG prompts fail with 'failed to find free space in the KV cache')
# thread counts must match CPUS in launch-snpvm.sh (vCPU count is part of the measurement)
EMBED_THREADS=${EMBED_THREADS:-32}; CHAT_THREADS=${CHAT_THREADS:-32}

fetch() {  # url dest sha
  if [ -f "$2" ] && echo "$3  $2" | sha256sum -c --status; then echo "ok (cached): $2"; return; fi
  curl -fL --retry 5 --retry-delay 5 -o "$2.part" "$1"
  echo "$3  $2.part" | sha256sum -c --status || { echo "sha256 mismatch: $1" >&2; rm -f "$2.part"; exit 1; }
  mv "$2.part" "$2"; echo "ok: $2"
}

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libgomp1 curl   # llama.cpp builds link OpenMP
mkdir -p "$LLM/models" /etc/attestrag
fetch "$LLAMA_URL" "$LLM/llama-$LLAMA_TAG.tar.gz" "$LLAMA_SHA"
rm -rf "$LLM/llama-$LLAMA_TAG" "$LLM/llama"
tar xzf "$LLM/llama-$LLAMA_TAG.tar.gz" -C "$LLM"
ln -s "llama-$LLAMA_TAG" "$LLM/llama"
rm -f "$LLM/llama-$LLAMA_TAG.tar.gz"
fetch "$EMBED_URL" "$LLM/models/$EMBED_FILE" "$EMBED_SHA"
fetch "$SMALL_URL" "$LLM/models/$SMALL_FILE" "$SMALL_SHA"
fetch "$BIG_URL/$BIG_FILE"  "$LLM/models/$BIG_FILE"  "$BIG_SHA"
fetch "$BIG_URL/$BIG_FILE2" "$LLM/models/$BIG_FILE2" "$BIG_SHA2"
"$LLM/llama/llama-server" --version 2>&1 | tail -1

cat > /etc/systemd/system/llama-embed.service <<UNIT
[Unit]
Description=llama.cpp embedding server (Qwen3-Embedding-0.6B)
After=local-fs.target
[Service]
Environment=LD_LIBRARY_PATH=$LLM/llama
ExecStart=$LLM/llama/llama-server -m $LLM/models/$EMBED_FILE --embedding --pooling last -c 2048 -b 2048 -ub 2048 \\
  --host 127.0.0.1 --port 8090 -t $EMBED_THREADS --alias embed --no-webui
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/llama-chat.service <<UNIT
[Unit]
Description=llama.cpp chat server ($CHAT_NAME)
After=local-fs.target
[Service]
Environment=LD_LIBRARY_PATH=$LLM/llama
ExecStart=$LLM/llama/llama-server -m $LLM/models/$CHAT_FILE -c 16384 -np 4 --host 127.0.0.1 --port 8091 \\
  -t $CHAT_THREADS --alias chat --no-webui
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

# keep an existing node.env: guest-qdrant-setup.sh prefixes NODE_ARGS and a re-run must not undo that
[ -f /etc/attestrag/node.env ] || cat > /etc/attestrag/node.env <<ENV
KBS_URL=$KBS_URL
DATA_DIR=/var/lib/attestrag
NODE_ARGS=--embed http://127.0.0.1:8090/v1 --llm http://127.0.0.1:8091/v1 --model chat --embed-model embed
ENV
cat /etc/attestrag/node.env

cat > /etc/systemd/system/attestrag-node.service <<UNIT
[Unit]
Description=AttestRAG node (attests to the KBS, then serves the RAG API on :8080)
After=network-online.target llama-embed.service llama-chat.service
Wants=network-online.target llama-embed.service llama-chat.service
RequiresMountsFor=/var/lib/attestrag
[Service]
EnvironmentFile=/etc/attestrag/node.env
ExecStart=/opt/attestrag/venv/bin/python -m attestrag.node_server --kbs \${KBS_URL} --data-dir \${DATA_DIR} \$NODE_ARGS
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable llama-embed.service llama-chat.service attestrag-node.service
du -sh "$LLM"
apt-get clean; rm -rf /var/lib/apt/lists/*
echo "installed: $LLM (llama.cpp $LLAMA_TAG, $EMBED_FILE, $CHAT_FILE); services enabled"
