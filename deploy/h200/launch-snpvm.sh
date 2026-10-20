#!/bin/bash
# Launch a CPU-only AMD SEV-SNP confidential VM. No sudo required (user in kvm group, /dev/sev 0660).
set -euo pipefail
D=$HOME/snp
QEMU=$D/qemu/bin/qemu-system-x86_64
OVMF=$HOME/snp/ovmf/2025.11-3ubuntu7.3/usr/share/ovmf/OVMF.amdsev.fd
DISK=$D/images/snpvm.qcow2
SEED=$D/images/seed.img
MEM=${MEM:-16G}
CPUS=${CPUS:-8}
SSH_PORT=${SSH_PORT:-2222}
MODE=${1:-snp}; [ $# -gt 0 ] && shift   # snp | plain
KERNEL=$D/images/vmlinuz
VERITY=${VERITY:-1}   # 1 = dm-verity read-only root (rootfs.raw + rootfs.hash) with tmpfs overlayroot; 0 = plain qcow2 root
if [ "$VERITY" = 1 ]; then
  INITRD=$D/images/initrd.verity.img
  ROOTHASH=$(cat $D/images/roothash.txt)
  APPEND=${APPEND:-"root=/dev/mapper/vroot ro rootflags=noload verity_dev=/dev/vda verity_hash=/dev/vdb roothash=$ROOTHASH overlayroot=tmpfs:recurse=0 console=ttyS0"}
  DISKS=(-drive file=$D/images/rootfs.raw,if=none,id=root0,format=raw,readonly=on -device virtio-blk-pci,drive=root0,disable-legacy=on,iommu_platform=true
         -drive file=$D/images/rootfs.hash,if=none,id=hash0,format=raw,readonly=on -device virtio-blk-pci,drive=hash0,disable-legacy=on,iommu_platform=true)
else
  INITRD=$D/images/initrd.img
  APPEND=${APPEND:-"root=LABEL=cloudimg-rootfs ro console=ttyS0"}
  DISKS=(-drive file="$DISK",if=none,id=disk0,format=qcow2 -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true -device scsi-hd,drive=disk0)
fi
KH=${KH:-on}   # kernel-hashes: on = measure kernel/initrd/cmdline into launch digest
DATA=${DATA:-$D/images/data.qcow2}   # optional persistent, untrusted data disk (encrypted index lives here)
if [ -f "$DATA" ]; then
  DISKS+=(-drive file="$DATA",if=none,id=data0,format=qcow2 -device virtio-blk-pci,drive=data0,serial=attestrag-data,disable-legacy=on,iommu_platform=true)
fi

MACHINE="q35,accel=kvm"
EXTRA=()
if [ "$MODE" = snp ]; then
  # policy 0x30000 = bit16 (SMT allowed) | bit17 (reserved, must be 1); no debug, no migration
  EXTRA=(-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000,kernel-hashes=$KH
         -machine confidential-guest-support=sev0)
  MACHINE="$MACHINE,memory-backend=ram1"
  EXTRA+=(-object memory-backend-memfd,id=ram1,size=$MEM,share=true,prealloc=false)
fi

exec "$QEMU" \
  -name snpvm -enable-kvm -machine "$MACHINE" -cpu EPYC-v4 -smp "$CPUS" -m "$MEM" \
  -bios "$OVMF" \
  -kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND" \
  "${DISKS[@]}" \
  -drive file="$SEED",if=none,id=seed0,format=raw,readonly=on -device virtio-blk-pci,drive=seed0,disable-legacy=on,iommu_platform=true \
  -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 -device virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=true,romfile= \
  -device virtio-rng-pci,disable-legacy=on,iommu_platform=true \
  -nographic -serial mon:stdio -no-reboot \
  "${EXTRA[@]}" "$@"
