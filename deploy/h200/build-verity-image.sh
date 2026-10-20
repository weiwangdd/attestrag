#!/bin/bash
# Build a dm-verity protected read-only root image from the golden qcow2 and
# compute the expected SEV-SNP launch measurement for it.
#
# Runs on the h200 host as a normal user (no sudo). Inputs are the golden qcow2
# (edit it by booting with VERITY=0, then poweroff cleanly), the guest kernel +
# verity-enabled initrd already extracted to $IMAGES, and the OVMF file.
#
# Usage:  build-verity-image.sh [OUTDIR]        (default: $HOME/snp/images/build-<date>)
# Env:    SNP=$HOME/snp  SRC_QCOW2=$SNP/images/snpvm.qcow2  SALT=<64 hex> (fixed salt => reproducible root hash)
#         CPUS=8  VCPU_TYPE=EPYC-v4  OVMF=...  KERNEL=...  INITRD=...
#
# Outputs in OUTDIR: rootfs.raw rootfs.hash roothash.txt verity.info append.txt
#                    expected-measurement.txt sha256sums.txt
set -euo pipefail

SNP=${SNP:-$HOME/snp}
IMAGES=$SNP/images
SRC_QCOW2=${SRC_QCOW2:-$IMAGES/snpvm.qcow2}
OVMF=${OVMF:-$SNP/ovmf/2025.11-3ubuntu7.3/usr/share/ovmf/OVMF.amdsev.fd}
KERNEL=${KERNEL:-$IMAGES/vmlinuz}
INITRD=${INITRD:-$IMAGES/initrd.verity.img}
CPUS=${CPUS:-8}
VCPU_TYPE=${VCPU_TYPE:-EPYC-v4}
MEASURE=${MEASURE:-$SNP/venv/bin/sev-snp-measure}
# Fixed salt + uuid make rootfs.hash and the root hash a pure function of the filesystem content.
SALT=${SALT:-7698ee41e191a7b63d5b570304467879157d57f548b6ed4155cd3f2b2a70769e}
VERITY_UUID=${VERITY_UUID:-990a400b-54f1-428b-8a55-ea80b285bcb3}
OUT=${1:-$IMAGES/build-$(date +%Y%m%d-%H%M%S)}
# Pin the timestamps e2fsck/resize2fs/debugfs write into the superblock (reproducible image).
export E2FSPROGS_FAKE_TIME=${E2FSPROGS_FAKE_TIME:-1700000000}
export E2FSCK_TIME=$E2FSPROGS_FAKE_TIME   # e2fsck's own clock (s_lastcheck in primary + backup superblocks)

for t in qemu-img sfdisk e2fsck resize2fs dumpe2fs debugfs veritysetup; do
  command -v $t >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done
for f in "$SRC_QCOW2" "$OVMF" "$KERNEL" "$INITRD" "$MEASURE"; do
  [ -e "$f" ] || { echo "missing input: $f" >&2; exit 1; }
done
pgrep -f "[q]emu-system-x86_64 .*$(basename "$SRC_QCOW2")" >/dev/null && { echo "golden qcow2 is in use by a running VM; power it off first" >&2; exit 1; }

mkdir -p "$OUT"; cd "$OUT"
echo "[1/6] qcow2 -> raw"
qemu-img convert -O raw "$SRC_QCOW2" disk.raw

echo "[2/6] extract root partition (partition 1)"
read -r START SECTORS < <(sfdisk -d disk.raw 2>/dev/null | grep -E 'disk\.raw1 ' | sed -E 's/.*start= *([0-9]+), size= *([0-9]+).*/\1 \2/')
[ -n "${START:-}" ] || { echo "could not find partition 1" >&2; exit 1; }
dd if=disk.raw of=rootfs.raw bs=4M iflag=skip_bytes,count_bytes skip=$((START*512)) count=$((SECTORS*512)) conv=sparse status=none
rm -f disk.raw

echo "[3/6] fsck + shrink to minimum"
e2fsck -fy rootfs.raw >/dev/null 2>&1 || true
resize2fs -M rootfs.raw >/dev/null 2>&1
BLKSZ=$(dumpe2fs -h rootfs.raw 2>/dev/null | awk -F: '/^Block size/{gsub(/ /,"",$2);print $2}')
BLKS=$(dumpe2fs -h rootfs.raw 2>/dev/null | awk -F: '/^Block count/{gsub(/ /,"",$2);print $2}')
truncate -s $((BLKSZ*BLKS)) rootfs.raw
e2fsck -fy rootfs.raw >/dev/null 2>&1 || true
# Normalise superblock counters that fsck/resize bump; timestamps are pinned via E2FSPROGS_FAKE_TIME.
for kv in "kbytes_written 0" "mnt_count 0" "lastcheck $E2FSPROGS_FAKE_TIME" "mtime 0"; do
  debugfs -w -R "set_super_value $kv" rootfs.raw >/dev/null 2>&1
done
echo "      rootfs.raw = $((BLKSZ*BLKS/1024/1024)) MiB"

echo "[4/6] dm-verity hash tree"
rm -f rootfs.hash
veritysetup format --data-block-size=4096 --hash-block-size=4096 --salt="$SALT" --uuid="$VERITY_UUID" rootfs.raw rootfs.hash > verity.info
ROOTHASH=$(awk '/Root hash/{print $3}' verity.info)
echo "$ROOTHASH" > roothash.txt
veritysetup verify rootfs.raw rootfs.hash "$ROOTHASH"
echo "      root hash = $ROOTHASH"

echo "[5/6] expected launch measurement"
APPEND="root=/dev/mapper/vroot ro rootflags=noload verity_dev=/dev/vda verity_hash=/dev/vdb roothash=$ROOTHASH overlayroot=tmpfs:recurse=0 console=ttyS0"
echo "$APPEND" > append.txt
"$MEASURE" --mode snp --vcpus "$CPUS" --vcpu-type "$VCPU_TYPE" --ovmf "$OVMF" \
  --kernel "$KERNEL" --initrd "$INITRD" --append "$APPEND" > expected-measurement.txt
echo "      measurement = $(cat expected-measurement.txt)"

echo "[6/6] checksums"
chmod a-w rootfs.raw rootfs.hash
sha256sum "$OVMF" "$KERNEL" "$INITRD" rootfs.raw rootfs.hash > sha256sums.txt
echo "done: $OUT"
echo "to deploy (VM stopped; previous images are read-only): chmod u+w $IMAGES/rootfs.{raw,hash}; cp $OUT/{rootfs.raw,rootfs.hash,roothash.txt,expected-measurement.txt} $IMAGES/"
