#!/bin/bash
# Put H200 GPU3 (0000:44:00.0) into confidential-computing mode and hand it to vfio-pci for the SNP guest.
# Run as root: sudo bash ~/snp/gpu3-cc-on.sh
set -u
D=0000:44:00.0; T=/home/weiwang/snp/gpu-admin-tools
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
G=$(basename $(readlink /sys/bus/pci/devices/$D/iommu_group)); chown weiwang /dev/vfio/$G; chmod 660 /dev/vfio/$G
chown weiwang /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null; chmod 660 /dev/iommu /dev/vfio/devices/vfio* 2>/dev/null   # iommufd backend (legacy type1 caps DMA mappings at 65535, too few for guest_memfd)
grep -q "weiwang.*memlock" /etc/security/limits.d/vfio.conf 2>/dev/null || printf "weiwang soft memlock unlimited\nweiwang hard memlock unlimited\n" > /etc/security/limits.d/vfio.conf
echo "== after"; echo "driver: $(basename $(readlink /sys/bus/pci/devices/$D/driver))  vfio group: $G  $(ls -la /dev/vfio/$G)"; nvidia-smi -L
