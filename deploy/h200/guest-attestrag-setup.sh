#!/bin/bash
# Run inside the guest (sudo) while the golden image is booted writable (VERITY=0):
# install attestRAG + its runtime deps into /opt/attestrag and prepare the mount
# point for the host-provided (untrusted, persistent) data disk.
#
#   host:  git archive --format=tgz -o attestrag-src.tgz HEAD
#          g -c attestrag-src.tgz /tmp/attestrag-src.tgz ; g -c guest-attestrag-setup.sh /tmp/
#   guest: sudo bash /tmp/guest-attestrag-setup.sh /tmp/attestrag-src.tgz ; sudo poweroff
#   host:  ./build-verity-image.sh  (new measurement -> update policies/h200-genoa.json)
#
# The data disk (launch-snpvm.sh: DATA=images/data.qcow2, virtio serial attestrag-data)
# is formatted once from inside the guest:  sudo mkfs.ext4 -L attestrag-data /dev/disk/by-id/virtio-attestrag-data
# The policy JSON is NOT baked into the image (it would have to contain the image's own
# measurement); the verifier side supplies it at runtime.
set -euo pipefail
SRC=${1:-/tmp/attestrag-src.tgz}
PREFIX=/opt/attestrag
[ -f "$SRC" ] || { echo "source tarball not found: $SRC" >&2; exit 1; }

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv
rm -rf "$PREFIX" && mkdir -p "$PREFIX/src"
tar xzf "$SRC" -C "$PREFIX/src"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$PREFIX/src" pytest nvidia-ml-py   # nvidia-ml-py: the node's GPU attester (NVML); harmless without a GPU
rm -f /usr/local/bin/attestrag-python   # never write through an old symlink (it points at the system python)
printf '#!/bin/sh\nexec %s/venv/bin/python "$@"\n' "$PREFIX" > /usr/local/bin/attestrag-python
chmod 755 /usr/local/bin/attestrag-python   # a symlink would defeat venv detection

mkdir -p /var/lib/attestrag
grep -q attestrag-data /etc/fstab || \
  echo 'LABEL=attestrag-data /var/lib/attestrag ext4 defaults,nofail,x-systemd.device-timeout=10 0 2' >> /etc/fstab

apt-get clean; rm -rf /var/lib/apt/lists/*
"$PREFIX/venv/bin/python" -c 'import attestrag, numpy, cryptography; print("attestrag ok; numpy", numpy.__version__, "cryptography", cryptography.__version__)'
echo "installed to $PREFIX; run tests with: cd $PREFIX/src && sudo $PREFIX/venv/bin/python -m pytest -q"
