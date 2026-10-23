#!/bin/bash
# Launch a CPU-only AMD SEV-SNP confidential VM. No sudo required (user in kvm group, /dev/sev 0660).
set -euo pipefail
D=$HOME/snp
QEMU=$D/qemu/bin/qemu-system-x86_64
OVMF=$HOME/snp/ovmf/2025.11-3ubuntu7.3/usr/share/ovmf/OVMF.amdsev.fd
DISK=$D/images/snpvm.qcow2
SEED=$D/images/seed.img
MEM=${MEM:-16G}
CPUS=${CPUS:-32}
SSH_PORT=${SSH_PORT:-2222}
NODE_PORT=${NODE_PORT:-8081}   # host port forwarded to the node service (guest :8080)
MODE=${1:-snp}; [ $# -gt 0 ] && shift   # snp | plain
# plain mode: the AmdSev OVMF only boots a -kernel through its SEV hashes table; use the standard build
[ "$MODE" = plain ] && OVMF=${PLAIN_OVMF:-/usr/share/ovmf/OVMF.fd}
KERNEL=$D/images/vmlinuz
VERITY=${VERITY:-1}   # 1 = dm-verity read-only root (rootfs.raw + rootfs.hash) with tmpfs overlayroot; 0 = plain qcow2 root
if [ "$VERITY" = 1 ]; then
  INITRD=$D/images/initrd.verity.img
  ROOTHASH=$(cat $D/images/roothash.txt)
  APPEND=${APPEND:-"root=/dev/mapper/vroot ro rootflags=noload verity_dev=/dev/vda verity_hash=/dev/vdb roothash=$ROOTHASH overlayroot=tmpfs:recurse=0 swiotlb=262144 console=ttyS0"}
  DISKS=(-drive file=$D/images/rootfs.raw,if=none,id=root0,format=raw,readonly=on -device virtio-blk-pci,drive=root0,disable-legacy=on,iommu_platform=true
         -drive file=$D/images/rootfs.hash,if=none,id=hash0,format=raw,readonly=on -device virtio-blk-pci,drive=hash0,disable-legacy=on,iommu_platform=true)
else
  INITRD=$D/images/initrd.img
  APPEND=${APPEND:-"root=LABEL=cloudimg-rootfs ro swiotlb=262144 console=ttyS0"}
  DISKS=(-drive file="$DISK",if=none,id=disk0,format=qcow2 -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true -device scsi-hd,drive=disk0)
fi
KH=${KH:-on}   # kernel-hashes: on = measure kernel/initrd/cmdline into launch digest
GPU=${GPU:-}   # optional PCI address of a GPU in CC mode bound to vfio-pci (e.g. 0000:44:00.0); passed through to the guest
GPUARGS=()   # a 512 GB hole needs > 40 phys bits, hence host-phys-bits=on on the -cpu line (CPUID is not in the launch measurement)
if [ -n "$GPU" ]; then
  # 64-bit MMIO window large enough for the H200 BARs (BAR1 = 256 GiB): tell both QEMU and OVMF
  # iommufd backend: the legacy type1 container caps DMA mappings at 65535, too few for guest_memfd shared/private conversion
  PCI_HOLE=${PCI_HOLE:-512G}          # QEMU 64-bit PCI hole (q35-pcihost); 1T made OVMF spin for >15 min
  MMIO64MB=${MMIO64MB:-524288}        # OVMF 64-bit MMIO aperture in MiB (H200 NVL BAR1 = 256 GiB, so >= 524288)
  # behind a PCIe root port with a real link speed: on the root bus the RM reports "Unknown PCIe speed"
  # (NV_ERR_INVALID_STATE) and cuInit fails with CUDA_ERROR_NOT_INITIALIZED although attestation works
  GPUARGS=(-object iommufd,id=iommufd0
           -device pcie-root-port,id=gpu-rp,bus=pcie.0,chassis=9,slot=9,x-speed=32,x-width=16
           -device vfio-pci,host="$GPU",bus=gpu-rp,iommufd=iommufd0
           -global q35-pcihost.pci-hole64-size="$PCI_HOLE" -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string="$MMIO64MB")
fi
DEBUGCON=${DEBUGCON:-}   # file for OVMF DEBUG output (isa-debugcon at 0x402), e.g. DEBUGCON=ovmf.debug.log
DBGARGS=()
[ -n "$DEBUGCON" ] && DBGARGS=(-debugcon file:"$DEBUGCON" -global isa-debugcon.iobase=0x402)
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
  -name snpvm -enable-kvm -machine "$MACHINE" -cpu EPYC-v4,host-phys-bits=on -smp "$CPUS" -m "$MEM" \
  -bios "$OVMF" \
  -kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND" \
  "${DISKS[@]}" "${GPUARGS[@]}" "${DBGARGS[@]}" \
  -drive file="$SEED",if=none,id=seed0,format=raw,readonly=on -device virtio-blk-pci,drive=seed0,disable-legacy=on,iommu_platform=true \
  -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${NODE_PORT}-:8080 -device virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=true,romfile= \
  -device virtio-rng-pci,disable-legacy=on,iommu_platform=true \
  -nographic -serial mon:stdio -no-reboot \
  "${EXTRA[@]}" "$@"
