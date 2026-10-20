#!/bin/bash
# Run inside the guest (sudo) while the golden image is booted writable (VERITY=0), after
# guest-llm-setup.sh: install Qdrant under /opt/qdrant with its storage on tmpfs (/run/qdrant,
# i.e. SEV-encrypted RAM, never on the host-visible disk) and switch the node to
# --vector-store qdrant. Persistence = sealed snapshots written by the node to the data disk.
set -euo pipefail
QDRANT_TAG=${QDRANT_TAG:-v1.19.2}
QDRANT_URL=https://github.com/qdrant/qdrant/releases/download/$QDRANT_TAG/qdrant-x86_64-unknown-linux-gnu.tar.gz
QDRANT_SHA=${QDRANT_SHA:-34a788a09a4cb278b5c6d2af96d9a6db30c8c7e88ae3550455f7a4d425bb8d4b}
Q=/opt/qdrant

mkdir -p "$Q"
curl -fL --retry 5 --retry-delay 5 -o "$Q/qdrant.tar.gz" "$QDRANT_URL"
echo "$QDRANT_SHA  $Q/qdrant.tar.gz" | sha256sum -c --status || { echo "sha256 mismatch: $QDRANT_URL" >&2; exit 1; }
tar xzf "$Q/qdrant.tar.gz" -C "$Q" && rm -f "$Q/qdrant.tar.gz"
"$Q/qdrant" --version

cat > "$Q/config.yaml" <<CFG
log_level: WARN
telemetry_disabled: true
service:
  host: 127.0.0.1
  http_port: 6333
  grpc_port: 6334
  enable_cors: false
storage:
  storage_path: /run/qdrant/storage
  snapshots_path: /run/qdrant/snapshots
  temp_path: /run/qdrant/tmp
CFG

cat > /etc/systemd/system/qdrant.service <<UNIT
[Unit]
Description=Qdrant vector database (storage on tmpfs = encrypted guest RAM; persisted as sealed snapshots by attestrag-node)
After=local-fs.target
[Service]
RuntimeDirectory=qdrant attestrag
RuntimeDirectoryMode=0755
ExecStart=$Q/qdrant --config-path $Q/config.yaml
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT

# node: start after qdrant, use it
sed -i 's/^After=network-online.target llama-embed.service llama-chat.service$/After=network-online.target llama-embed.service llama-chat.service qdrant.service/;
        s/^Wants=network-online.target llama-embed.service llama-chat.service$/Wants=network-online.target llama-embed.service llama-chat.service qdrant.service/' \
  /etc/systemd/system/attestrag-node.service
grep -q -- '--vector-store qdrant' /etc/attestrag/node.env || \
  sed -i 's|^NODE_ARGS=|NODE_ARGS=--vector-store qdrant --qdrant-url http://127.0.0.1:6333 |' /etc/attestrag/node.env
cat /etc/attestrag/node.env
systemctl daemon-reload
systemctl enable qdrant.service
echo "installed: $Q ($QDRANT_TAG); storage on /run/qdrant (tmpfs); node uses --vector-store qdrant"
