# Intel TDX on Google Cloud (C3)

The same code as on the SEV-SNP host, inside a TDX Confidential VM. Verified 2026-10-28 on a
`c3-standard-4` in `us-central1-b` (Sapphire Rapids 8481C, Ubuntu 24.04, kernel 7.0.0-gcp).

```
gcloud compute instances create tdx-1 --zone us-central1-b --machine-type c3-standard-4 \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 30GB \
  --metadata ssh-keys="<user>:<ssh public key>"
```

A plain C3 looks identical from the outside: check `grep -c tdx_guest /proc/cpuinfo` (one line per
vCPU) and `dmesg | grep "tdx: Guest detected"`. Inside the TD:

```
sudo apt-get install -y python3-venv && python3 -m venv ~/venv && ~/venv/bin/pip install <attestrag source>
sudo ~/venv/bin/python -m attestrag.demo --snp                      # no policy: prints the observed MRTD/TCB (TOFU)
sudo ~/venv/bin/python -m attestrag.demo --snp --policy policies/gcp-c3-tdx.json
# three processes: KBS, node (--attester tdx), client
~/venv/bin/python -m attestrag.kbs_server --policy policies/gcp-c3-tdx.json --keys kbs-keys.json
sudo ~/venv/bin/python -m attestrag.node_server --attester tdx --kbs http://127.0.0.1:8800 --kbs-pubkey $(~/venv/bin/python -m attestrag.kbs_server --keys kbs-keys.json --print-pubkey)
~/venv/bin/python -m attestrag.sdk --node http://127.0.0.1:8080 --policy policies/gcp-c3-tdx.json ask "..."
```

The attester uses configfs-tsm exactly like the SNP one (`provider` = `tdx_guest`; `outblob` is the
DCAP v4 quote, 8,000 bytes, PCK chain inside). The verifier (`attestrag/attest/tdx.py`) needs the
Intel SGX Root CA pin (in the code) and Intel PCS for the platform's TCB info and the QE identity,
cached under `~/.cache/attestrag/pcs` (`--pcs-cache`). `policies/gcp-c3-tdx.json` pins MRTD and the
TCB integers observed (status rank 4 = UpToDate, PCE SVN 13, TDX module SVN 15, QE SVN 6, TCB
evaluation 20). RTMR0-3 are in the claims (`extra`) but not pinned: they change with every kernel
update of the cloud image. The golden quote and its PCS collateral are `tests/fixtures/tdx/gcp-c3`.
