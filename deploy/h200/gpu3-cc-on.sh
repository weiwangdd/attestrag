#!/bin/bash
# Put H200 GPU3 (0000:44:00.0) into confidential-computing mode and hand it to vfio-pci for the SNP guest.
# Run as root: sudo bash ~/snp/gpu3-cc-on.sh
set -u
U=${SUDO_USER:-$USER}; H=$(getent passwd "$U" | cut -d: -f6)   # the unprivileged user who launches QEMU
D=0000:44:00.0; T=${GPU_ADMIN_TOOLS:-$H/snp/gpu-admin-tools}
echo "== before"; nvidia-smi -i 3 --query-gpu=index,pci.bus_id,memory.used --format=csv,noheader
nvidia-smi -i 3 -pm 0
cd $T && python3 nvidia_gpu_tools.py --devices 44:00.0 --query-cc-mode
python3 nvidia_gpu_tools.py --devices 44:00.0 --set-cc-mode=on --reset-after-cc-mode-switch
python3 nvidia_gpu_tools.py --devices 44:00.0 --query-cc-mode
echo "== nvidia-smi view"; nvidia-smi conf-compute -i 3 -q 2>&1 | grep -E "CC State|Ready State|Capabilities"
echo "== bind to vfio-pci"; modprobe vfio-pci
[ -e /sys/bus/pci/devices/$D/driver ] && echo $D > /sys/bus/pci/devices/$D/driver/unbind
echo vfio-pci > /sys/bus/pci/devices/$D/driver_override
echo $D > /sys/bus/pci/drivers/vfio-pci/bind
G=$(basename $(readlink /sys/bus/pci/devices/$D/iommu_group)); chown "$U" /dev/vfio/$G; chmod 660 /dev/vfio/$G
chown "$U" /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; chmod 660 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null   # iommufd backend (legacy type1 caps DMA mappings at 65535, too few for guest_memfd)
grep -q "^$U .*memlock" /etc/security/limits.d/vfio.conf 2>/dev/null || printf "%s soft memlock unlimited\n%s hard memlock unlimited\n" "$U" "$U" > /etc/security/limits.d/vfio.conf
echo "== after"; echo "driver: $(basename $(readlink /sys/bus/pci/devices/$D/driver))  vfio group: $G  $(ls -la /dev/vfio/$G)"; nvidia-smi -L
