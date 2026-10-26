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
| `launch-snpvm.sh [snp\|plain]` | host | start the VM. Env: `VERITY=1/0`, `KH=on/off`, `CPUS`, `MEM`, `SSH_PORT`, `GPU=<pci addr>` (pass a CC-mode GPU through; `PCI_HOLE`, `MMIO64MB` size the 64-bit MMIO window, `DEBUGCON=file` captures OVMF debug output), `VMNAME` (a second VM needs its own name, ports and `DATA`). Default = SNP + kernel-hashes + dm-verity root + tmpfs overlay |
| `g 'cmd'` / `g -c file dest` | host | run a command in / copy a file into the guest (ssh port 2222) |
| `build-verity-image.sh [outdir]` | host | golden qcow2 -> `rootfs.raw` + `rootfs.hash` + root hash + expected measurement (fixed salt, reproducible) |
| `guest-verity-setup.sh` | guest (sudo) | one-time: initramfs hook + local-top script for dm-verity, fstab fixes, rebuild initrd |
| `e2e-test.sh` | host | end-to-end check of the running guest: SNP active, verity root bound to the expected root hash, data disk rw, PSP-signed measurement == `images/expected-measurement.txt`, demo allowed with the expected policy and denied with a wrong measurement / too-high min TCB. `POLICY=file` to test a given policy, `AUTO_LAUNCH=1` to start the guest |
| `guest-llm-setup.sh` | guest (sudo) | llama.cpp b11753 + Qwen3-Embedding-0.6B Q8_0 + Qwen2.5-7B-Instruct Q4_K_M (two official GGUF shards; `CHAT_MODEL=1.5b` selects the 1.5B of the CPU-only baseline, both files stay in the image) into `/opt/llm` (sha256-pinned, inside the measured image); systemd units `llama-embed` (:8090), `llama-chat` (:8091), `attestrag-node` (boots into attest -> key -> serve; KBS URL in `/etc/attestrag/node.env`) |
| `guest-qdrant-setup.sh` | guest (sudo) | Qdrant v1.19.2 (sha256-pinned) into `/opt/qdrant`, storage on `/run/qdrant` (tmpfs), `qdrant.service`; node switched to `--vector-store qdrant` (sealed snapshots in `/var/lib/attestrag`) |
| `guest-attestrag-setup.sh <src.tgz>` | guest (sudo) | install attestRAG + numpy/cryptography into `/opt/attestrag` (venv), fstab entry for the data disk. Source tarball: `git archive --format=tgz -o attestrag-src.tgz HEAD` |
| `guest-gpu-setup.sh` | guest (sudo) | NVIDIA 580 open kernel modules + user space, llama.cpp CUDA build (sha256-pinned) next to the CPU build, `run-llama.sh` selector (CUDA when a GPU is present), `nvidia-cc-ready.service` (persistence mode + CC ready state before the servers start), `nvidia-ml-py` for the node's GPU attester, `--gpu auto` in `node.env` |
| `a1-baseline.sh` (h200 only) | host | the unprotected baseline: GPU3 to normal mode, `launch-snpvm.sh plain` (standard OVMF; the AmdSev build only boots a `-kernel` through its SEV hashes table), node `--attester mock-insecure`, KBS/client `--insecure-mock` with `policies/insecure-baseline.json`, then back to CC mode and `relaunch.sh`. Finding: the NVIDIA driver refuses a normal-mode GPU inside a CVM (`Cannot attach gpu`), so the CVM and GPU-CC halves cannot be measured separately |
| `infonly-baseline.sh` (h200 only) | host | the inference-only-TEE baseline: a second plain VM (`VMNAME=plainvm`, own ports and index copy) runs the retrieval side with mock attestation and calls the production CVM's llama-chat over an ssh tunnel; runs RGB, then tears everything down |
| `gpu3-cc-on.sh` | host (sudo) | put GPU3 (`0000:44:00.0`) into CC mode with NVIDIA's gpu-admin-tools, hand it to `vfio-pci`, open `/dev/vfio/<group>`, `/dev/iommu` and the vfio cdev to the launching user |
| `gpu3-release-cycle.sh` | host | the unbind only completes once no process holds `/dev/nvidia3`, and every CUDA/NVML process on the host opens all four device nodes: stops the host's GPU services and daemons in order, waits for the detach, starts them again (5–10 min outage of the other three GPUs' services) |
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
`g 'journalctl -u attestrag-node -n 20'`. CPU-only: ~1.5 GB of models, 32 vCPUs
(32 threads for each llama-server, chat with a 16k unified KV cache for its 4 slots; 8 vCPUs with 2+6 threads
ingested 0.3 chunks/s and `-c 4096` failed under 2 concurrent users, see docs/benchmarks.md).

## Vector database (step 3b)

Qdrant runs in the guest with its storage on tmpfs, so vectors and chunk text only ever
exist in encrypted guest RAM. After each ingest the node snapshots the collection, seals the
snapshot with the KBS-released key and writes `qdrant-<collection>.snapshot.enc` to the data
disk; at start it unseals into `/run/attestrag` (tmpfs) and recovers the collection. A host
that edits or swaps the file gets an AES-GCM tag failure, and the node refuses to start.

## GPU confidential computing (step 4)

One H200 NVL (GPU3, `0000:44:00.0`) is passed through to the CVM in NVIDIA confidential-computing
mode; the other three GPUs keep serving the host's own workloads. What it took, in order:

1. **Host**: `sudo bash gpu3-cc-on.sh` switches the GPU to CC mode (gpu-admin-tools, reset) and
   binds it to `vfio-pci`. The unbind blocks inside the driver until every holder of `/dev/nvidia3`
   is gone, and NVML opens *all* `/dev/nvidiaN` nodes in every CUDA process, so the host's vLLM
   services (user units) and `nvidia-dcgm` / `nvidia-persistenced` all count: `gpu3-release-cycle.sh`
   stops them, lets the detach finish and restarts them. While the GPU is half-detached, every new
   CUDA process on the host fails with `cudaGetDeviceCount: invalid device ordinal` (NVML counts 4,
   CUDA 3), so the cycle is the only way forward once the switch has started.
2. **Launch**: `GPU=0000:44:00.0 ./launch-snpvm.sh snp` (or `GPU=... bash relaunch.sh`). The
   additions, each the fix for a failure on the way:
   `-cpu EPYC-v4,host-phys-bits=on` (a 512 GB hole needs more than the model's 40 physical bits;
   CPUID is not in the launch measurement), `-object iommufd` + `iommufd=` on the device (the legacy
   type1 container caps DMA mappings at 65,535, too few for guest_memfd shared/private conversion),
   a 512 GB `pci-hole64-size` and `X-PciMmio64Mb=524288` (H200 NVL BAR1 is 256 GB; with a 1 TB
   window OVMF spun in its page-table walk for over 15 minutes), and a `pcie-root-port` with
   `x-speed=32,x-width=16` in front of the GPU (on the root bus the driver reports "Unknown PCIe
   speed", and `cuInit` returns `CUDA_ERROR_NOT_INITIALIZED` although attestation works).
3. **Guest** (`guest-gpu-setup.sh`, baked into the image): the Ubuntu `linux-modules-nvidia-580-open`
   package needs `depmod` run in the image build or `systemd-modules-load` cannot find `nvidia`;
   `nvidia-cc-ready.service` sets persistence mode and the CC ready state before llama-embed,
   llama-chat and the node start (CUDA refuses to initialise until the ready state is set);
   `run-llama.sh` picks the CUDA build with `-ngl 99` when `/dev/nvidia0` exists.
4. **Evidence**: the node (`--gpu auto`) fetches the SPDM GET_MEASUREMENTS transcript and the
   attestation-key chain through NVML for every CC GPU and ships them with the SNP report. The
   verifier (`attestrag/attest/nvidia.py`) chains the AK certificate to the pinned NVIDIA Device
   Identity CA, checks the ECDSA P-384 signature over request || response, checks the *request*
   nonce against `gpu_report_data(cpu_rd)` (the response nonce is chosen by the GPU, as SPDM
   specifies), matches the firmware ID in the certificate against the report, and reduces the 64
   DMTF measurement blocks to one SHA-384 that the policy pins (`allowed_gpu_measurements`,
   `require_gpu` in `policies/h200-genoa.json`). A real transcript is the golden case in
   `tests/fixtures/nvidia/h200/`. Since step 12 the CPU report also commits to the GPU's identity:
   `cpu_rd = H("attestrag-rd-v2" || nonce || pk || SHA-384(AK certificate))`, so a GPU half swapped in
   transit by an operator with another confidential GPU no longer matches (the attack the Tamarin
   model in `formal/` found against the first binding).
5. **NVIDIA services** (`--gpu-rim` on the KBS, the SDK and the benchmark; `attestrag/attest/nvidia_rim.py`):
   the verifier fetches NVIDIA's reference manifests for the driver (`NV_GPU_DRIVER_GH100_<version>`)
   and the VBIOS (`NV_GPU_VBIOS_<project>_<sku>_<chip>_<vbios>`), checks each manifest's certificate
   chain to the pinned NVIDIA CoRIM signing root and its XML signature (`signxml`), and compares every
   active manifest entry with the report's measurement block of the same position (index 35 is skipped
   when NVDEC0 is disabled, as on this card in CC mode); it also asks NVIDIA's OCSP responder about
   every CA certificate of the attestation-key chain and of the manifest chains (delegated responder,
   nonce, validity window). Results land in the claims (`rim_driver`, `rim_vbios`, `rim_matched`,
   `ocsp`), and the policy can insist on them (`require_gpu_ocsp`, `require_gpu_rim`). Manifests and
   OCSP responses are cached under `~/.cache/attestrag/nvidia`. As of 2026-10-23 NVIDIA publishes the
   driver manifest for 580.178.04 (its 22 active entries match this H200) but no VBIOS manifest for
   `1010_0230_894_9600B70002` (the id is built exactly as nvtrust does), so the h200 policy requires
   OCSP and records, but does not require, the manifests; the pinned composite digest covers the VBIOS
   blocks either way.

The host sees the GPU as `vfio-pci` and nothing else: `nvidia-smi -L` lists three GPUs. Inside the
guest `nvidia-smi conf-compute -q` reports `CC State: ON`, `CPU CC Capabilities: AMD SEV-SNP`.
Benchmark numbers for the GPU configuration are in `docs/benchmarks.md`.

## Measurement chain

PSP signs the launch digest over: OVMF + initial vCPU state (count, model) + kernel-hashes table (vmlinuz, initrd, cmdline).
The cmdline carries `roothash=`, so the dm-verity root hash, and with it every block of the root filesystem, is bound to the measurement.
Guest writes go to a tmpfs overlay and are lost at reboot.

Verifier inputs: `baseline/` (root hash, expected measurement, sha256 of OVMF/kernel/initrd/rootfs/hash). The same values in policy-engine form are in `policies/h200-genoa.json` (measurement allow-list, min TCB `boot=10 tee=0 snp=24 ucode=88`, guest policy `0x30000`); a real report from this VM is the golden sample in `tests/fixtures/snp/h200-genoa/`.
Checks (all implemented in `attestrag/attest/snp.py` + `attestrag/policy/engine.py`): cert chain ARK->ASK->VCEK, report signature, `measurement == expected`, `policy == 0x30000`, `tcb >= min`, `report_data == nonce`.
