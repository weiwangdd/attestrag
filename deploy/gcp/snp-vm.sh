#!/usr/bin/env bash
# Run AttestRAG on a GCP N2D Confidential VM with AMD SEV-SNP.
#
#   deploy/gcp/snp-vm.sh up      create the VM (Spot by default), install, run tests + SNP demo
#   deploy/gcp/snp-vm.sh demo    re-sync the working tree and re-run the SNP demo
#   deploy/gcp/snp-vm.sh ssh     open a shell on the VM
#   deploy/gcp/snp-vm.sh status  show the VM
#   deploy/gcp/snp-vm.sh down    delete the VM (stop paying)
#
# Env: GCP_PROJECT (default: gcloud config), GCP_ZONE (us-central1-a),
#      VM_NAME (attestrag-snp), MACHINE_TYPE (n2d-standard-2), SPOT (1; 0 = on-demand),
#      DRY_RUN=1 prints gcloud commands instead of running them.
# SEV-SNP on N2D needs the AMD Milan platform and a supporting zone, e.g.
# us-central1-{a,b,c}, europe-west4-{a,b,c}, asia-southeast1-{a,b,c}.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
[ "${DRY_RUN:-0}" = 1 ] && PROJECT="${PROJECT:-my-project}"
ZONE="${GCP_ZONE:-us-central1-a}"
NAME="${VM_NAME:-attestrag-snp}"
MACHINE="${MACHINE_TYPE:-n2d-standard-2}"
SPOT="${SPOT:-1}"
DRY_RUN="${DRY_RUN:-0}"
REMOTE_DIR="attestrag"

die() { echo "error: $*" >&2; exit 1; }
run() {
  if [ "$DRY_RUN" = 1 ]; then printf '+'; printf ' %q' "$@"; echo; else "$@"; fi
}

[ -n "$PROJECT" ] || die "set GCP_PROJECT or run: gcloud config set project <id>"
[ "$DRY_RUN" = 1 ] || command -v gcloud >/dev/null || die "gcloud not found (https://cloud.google.com/sdk/docs/install)"
G=(--project "$PROJECT" --zone "$ZONE")

up() {
  local spot_flags=()
  if [ "$SPOT" = 1 ]; then
    spot_flags=(--provisioning-model=SPOT --instance-termination-action=DELETE)
  fi
  run gcloud compute instances create "$NAME" "${G[@]}" \
    --machine-type="$MACHINE" \
    --min-cpu-platform="AMD Milan" \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
    --boot-disk-size=20GB \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --labels=app=attestrag \
    "${spot_flags[@]}"
  wait_ssh
  sync_code
  run gcloud compute ssh "$NAME" "${G[@]}" --command "$(remote_setup)"
  demo_only
}

wait_ssh() {
  [ "$DRY_RUN" = 1 ] && { echo "+ (wait for ssh)"; return; }
  for i in $(seq 1 30); do
    if gcloud compute ssh "$NAME" "${G[@]}" --command true --quiet >/dev/null 2>&1; then return; fi
    echo "waiting for ssh ($i/30)..."; sleep 10
  done
  die "VM did not become reachable over ssh"
}

sync_code() {
  local tgz; tgz="$(mktemp -t attestrag.XXXXXX).tgz"
  # tracked + untracked-but-not-ignored files, so uncommitted edits are included
  (cd "$ROOT" && git ls-files -co --exclude-standard -z | xargs -0 tar czf "$tgz")
  run gcloud compute scp "$tgz" "$NAME:/tmp/attestrag.tgz" "${G[@]}"
  rm -f "$tgz"
  run gcloud compute ssh "$NAME" "${G[@]}" --command \
    "rm -rf ~/$REMOTE_DIR/attestrag ~/$REMOTE_DIR/tests && mkdir -p ~/$REMOTE_DIR && tar xzf /tmp/attestrag.tgz -C ~/$REMOTE_DIR"
}

remote_setup() {
  cat <<REMOTE
set -euxo pipefail
sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv
cd ~/$REMOTE_DIR
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e '.[dev]'
.venv/bin/python -m pytest -q
REMOTE
}

demo_only() {
  run gcloud compute ssh "$NAME" "${G[@]}" --command "$(cat <<REMOTE
set -euo pipefail
cd ~/$REMOTE_DIR
uname -r
sudo modprobe sev-guest 2>/dev/null || true
mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
sudo dmesg | grep -i -m3 'SEV-SNP' || true
ls -d /sys/kernel/config/tsm/report || { echo 'configfs-tsm missing: need kernel >= 6.7 with CONFIG_TSM_REPORTS'; exit 1; }
sudo .venv/bin/python -m attestrag.demo --snp --product Milan
REMOTE
)"
}

case "${1:-}" in
  up) up ;;
  demo) sync_code; run gcloud compute ssh "$NAME" "${G[@]}" --command "$(remote_setup)"; demo_only ;;
  ssh) run gcloud compute ssh "$NAME" "${G[@]}" ;;
  status) run gcloud compute instances describe "$NAME" "${G[@]}" \
            --format="table(name,status,machineType.basename(),confidentialInstanceConfig,scheduling.provisioningModel)" ;;
  down) run gcloud compute instances delete "$NAME" "${G[@]}" --quiet ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
