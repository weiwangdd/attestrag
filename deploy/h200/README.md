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
| `images/data.qcow2` | persistent, untrusted data disk (virtio serial `attestrag-data`, mounted at `/var/lib/attestrag`; holds the AES-GCM encrypted index). Format once from the guest: `sudo mkfs.ext4 -L attestrag-data /dev/disk/by-id/virtio-attestrag-data` |
| `snpvm_key` | ssh key for the guest |

## Scripts

| script | runs on | purpose |
|---|---|---|
| `launch-snpvm.sh [snp\|plain]` | host | start the VM. Env: `VERITY=1/0`, `KH=on/off`, `CPUS`, `MEM`, `SSH_PORT`. Default = SNP + kernel-hashes + dm-verity root + tmpfs overlay |
| `g 'cmd'` / `g -c file dest` | host | run a command in / copy a file into the guest (ssh port 2222) |
| `build-verity-image.sh [outdir]` | host | golden qcow2 -> `rootfs.raw` + `rootfs.hash` + root hash + expected measurement (fixed salt, reproducible) |
| `guest-verity-setup.sh` | guest (sudo) | one-time: initramfs hook + local-top script for dm-verity, fstab fixes, rebuild initrd |
| `e2e-test.sh` | host | end-to-end check of the running guest: SNP active, verity root bound to the expected root hash, data disk rw, PSP-signed measurement == `images/expected-measurement.txt`, demo allowed with the expected policy and denied with a wrong measurement / too-high min TCB. `POLICY=file` to test a given policy, `AUTO_LAUNCH=1` to start the guest |
| `guest-llm-setup.sh` | guest (sudo) | llama.cpp b11753 + Qwen3-Embedding-0.6B Q8_0 + Qwen2.5-1.5B-Instruct Q4_K_M into `/opt/llm` (sha256-pinned, inside the measured image); systemd units `llama-embed` (:8090), `llama-chat` (:8091), `attestrag-node` (boots into attest -> key -> serve; KBS URL in `/etc/attestrag/node.env`) |
| `guest-qdrant-setup.sh` | guest (sudo) | Qdrant v1.19.2 (sha256-pinned) into `/opt/qdrant`, storage on `/run/qdrant` (tmpfs), `qdrant.service`; node switched to `--vector-store qdrant` (sealed snapshots in `/var/lib/attestrag`) |
| `guest-attestrag-setup.sh <src.tgz>` | guest (sudo) | install attestRAG + numpy/cryptography into `/opt/attestrag` (venv), fstab entry for the data disk. Source tarball: `git archive --format=tgz -o attestrag-src.tgz HEAD` |
| `guest-snpguest-setup.sh` | guest | download `snpguest` v0.10.0 |
| `guest-attest.sh` | guest (sudo) | fetch an attestation report through configfs-tsm, no external tools |
| `guest-verify.sh` | guest | request report, fetch ARK/ASK/VCEK from AMD KDS, verify chain + signature |

Typical cycle after changing the guest image:

```
VERITY=0 ./launch-snpvm.sh snp      # boot writable golden image, make changes, `sudo poweroff`
./build-verity-image.sh             # new rootfs.raw/.hash/roothash/measurement in images/build-<ts>/
chmod u+w images/rootfs.{raw,hash}   # outputs are read-only
cp images/build-<ts>/{rootfs.raw,rootfs.hash,roothash.txt,expected-measurement.txt} images/
./launch-snpvm.sh snp               # boot the verity image
```

The guest image never contains the policy (it would have to include its own measurement);
the verifier side supplies it. To run the in-guest demo against the published policy:

```
g -c ../../policies/h200-genoa.json /tmp/policy.json
g 'sudo /opt/attestrag/venv/bin/python -m attestrag.demo --snp --policy /tmp/policy.json'
```

If the guest kernel changes, re-extract `vmlinuz` and `initrd.verity.img` from the guest first (they are part of the measurement).

The launcher passes `-no-reboot`: a `reboot` inside the guest ends the QEMU process; start it again from the host. Stop with `pkill -f "[q]emu-system-x86_64 -name snpvm"` (the bracket keeps pkill from matching its own ssh session).

## KBS outside, node inside (step 2)

```
# host: KBS with the published policy; keys persisted in ~/snp/kbs-keys.json (0600)
~/snp/venv/bin/python -m attestrag.kbs_server --policy policy-h200.json --keys ~/snp/kbs-keys.json --listen 127.0.0.1:8800
# guest: node attests to the KBS (host is 10.0.2.2 from inside slirp), serves :8080 -> host :8081
g 'sudo nohup /opt/attestrag/venv/bin/python -m attestrag.node_server --kbs http://10.0.2.2:8800 --data-dir /var/lib/attestrag > /tmp/node.log 2>&1 &'
# host (or anywhere that can reach :8081): client verifies, then uploads / asks
~/snp/venv/bin/python -m attestrag.sdk --node http://127.0.0.1:8081 --policy policy-h200.json ask "..."
```

`attestrag` is installed into the host's `~/snp/venv` from the same source tarball as the guest.

## Self-starting CVM (step 3)

With `guest-llm-setup.sh` applied, a boot of the verity image runs the two llama-servers
and `attestrag-node.service`, which attests to `KBS_URL` (default `http://10.0.2.2:8800`,
the host as seen through slirp), receives the index key and serves `:8080`. If the KBS is
down the unit retries every 10 s. Check with `g 'systemctl status attestrag-node'` and
`g 'journalctl -u attestrag-node -n 20'`. CPU-only: ~1.5 GB of models, 8 vCPUs
(2 threads embedding, 6 chat).

## Vector database (step 3b)

Qdrant runs in the guest with its storage on tmpfs, so vectors and chunk text only ever
exist in encrypted guest RAM. After each ingest the node snapshots the collection, seals the
snapshot with the KBS-released key and writes `qdrant-<collection>.snapshot.enc` to the data
disk; at start it unseals into `/run/attestrag` (tmpfs) and recovers the collection. A host
that edits or swaps the file gets an AES-GCM tag failure, and the node refuses to start.

## Measurement chain

PSP signs the launch digest over: OVMF + initial vCPU state (count, model) + kernel-hashes table (vmlinuz, initrd, cmdline).
The cmdline carries `roothash=`, so the dm-verity root hash, and with it every block of the root filesystem, is bound to the measurement.
Guest writes go to a tmpfs overlay and are lost at reboot.

Verifier inputs: `baseline/` (root hash, expected measurement, sha256 of OVMF/kernel/initrd/rootfs/hash). The same values in policy-engine form are in `policies/h200-genoa.json` (measurement allow-list, min TCB `boot=10 tee=0 snp=24 ucode=88`, guest policy `0x30000`); a real report from this VM is the golden sample in `tests/fixtures/snp/h200-genoa/`.
Checks (all implemented in `attestrag/attest/snp.py` + `attestrag/policy/engine.py`): cert chain ARK->ASK->VCEK, report signature, `measurement == expected`, `policy == 0x30000`, `tcb >= min`, `report_data == nonce`.
