# deploy/h200: SEV-SNP confidential VM on the h200 host

State of the h200 host (quadtopus, Gigabyte G494-ZB4-AAP2, 2x EPYC 9554, 4x H200 NVL) as of 2026-10-19.
Host side: BIOS SEV-SNP enabled, kernel 7.0.0-38 HWE, NVIDIA open driver 580.178.04, `kvm_amd sev_snp=Y`.
Everything below runs as user `weiwang` without sudo (user in `kvm` group, `/dev/sev` is 0660 root:kvm via udev rule).

## Layout on h200 (`~/snp`)

| path | what |
|---|---|
| `qemu/` | QEMU 11.1.2 built from source (distro 8.2 has no `sev-snp-guest`) |
| `ovmf/2025.11-3ubuntu7.3/.../OVMF.amdsev.fd` | firmware; Ubuntu 24.04's 2024.02 build does not boot under upstream QEMU SNP |
| `venv/` | `sev-snp-measure` |
| `images/snpvm.qcow2` | golden image (noble cloud image overlay); edit by booting `VERITY=0` |
| `images/vmlinuz`, `images/initrd.verity.img` | guest kernel + initrd with dm-verity hook, extracted from the guest |
| `images/rootfs.raw`, `images/rootfs.hash`, `images/roothash.txt` | dm-verity read-only root + hash tree |
| `images/seed.img` | cloud-init NoCloud seed (ssh key for `ubuntu`) |
| `snpvm_key` | ssh key for the guest |

## Scripts

| script | runs on | purpose |
|---|---|---|
| `launch-snpvm.sh [snp\|plain]` | host | start the VM. Env: `VERITY=1/0`, `KH=on/off`, `CPUS`, `MEM`, `SSH_PORT`. Default = SNP + kernel-hashes + dm-verity root + tmpfs overlay |
| `g 'cmd'` / `g -c file dest` | host | run a command in / copy a file into the guest (ssh port 2222) |
| `build-verity-image.sh [outdir]` | host | golden qcow2 -> `rootfs.raw` + `rootfs.hash` + root hash + expected measurement (fixed salt, reproducible) |
| `guest-verity-setup.sh` | guest (sudo) | one-time: initramfs hook + local-top script for dm-verity, fstab fixes, rebuild initrd |
| `guest-snpguest-setup.sh` | guest | download `snpguest` v0.10.0 |
| `guest-attest.sh` | guest (sudo) | fetch an attestation report through configfs-tsm, no external tools |
| `guest-verify.sh` | guest | request report, fetch ARK/ASK/VCEK from AMD KDS, verify chain + signature |

Typical cycle after changing the guest image:

```
VERITY=0 ./launch-snpvm.sh snp      # boot writable golden image, make changes, `sudo poweroff`
./build-verity-image.sh             # new rootfs.raw/.hash/roothash/measurement in images/build-<ts>/
cp images/build-<ts>/{rootfs.raw,rootfs.hash,roothash.txt,expected-measurement.txt} images/
./launch-snpvm.sh snp               # boot the verity image
```

If the guest kernel changes, re-extract `vmlinuz` and `initrd.verity.img` from the guest first (they are part of the measurement).

## Measurement chain

PSP signs the launch digest over: OVMF + initial vCPU state (count, model) + kernel-hashes table (vmlinuz, initrd, cmdline).
The cmdline carries `roothash=`, so the dm-verity root hash, and with it every block of the root filesystem, is bound to the measurement.
Guest writes go to a tmpfs overlay and are lost at reboot.

Verifier inputs: `baseline/` (root hash, expected measurement, sha256 of OVMF/kernel/initrd/rootfs/hash). The same values in policy-engine form are in `policies/h200-genoa.json` (measurement allow-list, min TCB `boot=10 tee=0 snp=24 ucode=88`, guest policy `0x30000`); a real report from this VM is the golden sample in `tests/fixtures/snp/h200-genoa/`.
Checks (all implemented in `attestrag/attest/snp.py` + `attestrag/policy/engine.py`): cert chain ARK->ASK->VCEK, report signature, `measurement == expected`, `policy == 0x30000`, `tcb >= min`, `report_data == nonce`.
