set -e
# 1. initramfs hook: ship veritysetup + dm-verity module
cat > /etc/initramfs-tools/hooks/verity <<'H'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/sbin/veritysetup /sbin
manual_add_modules dm-mod dm-verity
H
chmod +x /etc/initramfs-tools/hooks/verity
# 2. local-top script: open verity root before root mount
cat > /etc/initramfs-tools/scripts/local-top/verity <<'S'
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0;; esac
. /scripts/functions
VDEV=""; VHDEV=""; VHASH=""
for x in $(cat /proc/cmdline); do
  case $x in
    verity_dev=*)  VDEV=${x#verity_dev=};;
    verity_hash=*) VHDEV=${x#verity_hash=};;
    roothash=*)    VHASH=${x#roothash=};;
  esac
done
[ -n "$VHASH" ] || exit 0
modprobe dm-mod || true; modprobe dm-verity || true
i=0; while { [ ! -b "$VDEV" ] || [ ! -b "$VHDEV" ]; } && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
log_begin_msg "Opening dm-verity root $VDEV (hash $VHDEV)"
veritysetup open "$VDEV" vroot "$VHDEV" "$VHASH" || panic "dm-verity: failed to open root"
i=0; while [ ! -b /dev/mapper/vroot ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
log_end_msg
S
chmod +x /etc/initramfs-tools/scripts/local-top/verity
# 3. fstab: /boot and /boot/efi will not exist on the verity root image
sed -i -E 's#^(LABEL=(BOOT|UEFI)\s)#\#\1#' /etc/fstab; cat /etc/fstab | grep -v '^#' | grep -v '^$'
# 4. sev-guest autoload, snpguest in PATH
echo sev-guest > /etc/modules-load.d/sev-guest.conf
install -m 755 /home/ubuntu/attest/snpguest /usr/local/bin/snpguest
# 5. rebuild initrd
update-initramfs -u -k $(uname -r) 2>&1 | tail -2
lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'veritysetup|dm-verity|local-top/verity|overlayroot' | head
chmod a+r /boot/initrd.img-$(uname -r)
sync
