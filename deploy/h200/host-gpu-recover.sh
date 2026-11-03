#!/bin/bash
# h200: bring host GPUs back after a stuck driver unbind or an NVLink-peer fault, then restart every GPU service.
#
# Why this exists: the four H200 NVL cards share an NVLink bridge. Every function-level reset of GPU3
# (gpu3-cc-on.sh's --reset-after-cc-mode-switch) throws "Xid 74 NVLink fatal error" on the other three;
# an idle peer loses CUDA (new contexts fail), a busy one escalates to Xid 119 (GSP timeout) and Xid 154
# (GPU Reset Required). A later `echo <bdf> > /sys/bus/pci/drivers/nvidia/unbind` then spins inside the
# driver for as long as any process holds a /dev/nvidiaN node (persistenced, DCGM, every vLLM), and the
# card is left as a zombie: no PCI driver, still listed in /proc/driver/nvidia/gpus, absent from nvidia-smi.
#
# Recovery, as verified on 2026-11-03: stop the holders -> the pending unbinds finish in seconds ->
# bind the card again. A card left in "Reset Required" refuses a plain bind (RmInitAdapter failed
# 0x62:0x40:2028, GSP firmware), so on failure: unbind, FLR through sysfs, bind again.
#
# Usage: bash host-gpu-recover.sh [bdf ...]      e.g. 0000:03:00.0 0000:04:00.0
#   no argument = every NVIDIA GPU that currently has no driver bound (the zombies; the vfio-pci GPU
#   of the CVM is bound and therefore never touched). Runs as weiwang (sudo -n). ~5 min outage.
set -u
USER_UNITS=${USER_UNITS:-"vllm-deepseek vllm-embed vllm-qwen3vl30b funasr-nano"}
DAEMONS=${DAEMONS:-"nvidia-dcgm nvidia-persistenced"}
PORTS=${PORTS:-"8000 8001 8002 8004"}
TORCH=${TORCH:-$HOME/.vllm/bin/python}
log() { echo "$(date +%T) $*"; }

if [ $# -gt 0 ]; then GPUS="$*"; else
  GPUS=""
  for b in $(lspci -D -d 10de: | awk '{print $1}'); do
    [ "$(lspci -s "$b" -n | awk '{print $2}')" = "0302:" ] || continue
    [ -e /sys/bus/pci/devices/$b/driver ] || GPUS="$GPUS $b"
  done
fi
[ -n "${GPUS// }" ] || { echo "no NVIDIA GPU without a driver; pass the bdf(s) to re-bind explicitly"; exit 1; }
log "GPUs to recover:$GPUS"

log "== stop GPU daemons and all GPU services"
sudo -n systemctl stop $DAEMONS
systemctl --user stop $USER_UNITS
for u in $USER_UNITS; do systemctl --user reset-failed "$u" 2>/dev/null; done

log "== wait for the driver to finish removing the cards (pending unbind writes exit by themselves)"
for i in $(seq 1 90); do
  left=""; for b in $GPUS; do [ -e /proc/driver/nvidia/gpus/$b ] && left="$left $b"; done
  [ -z "$left" ] && { log "removal complete"; break; }
  if [ $((i % 15)) -eq 0 ]; then log "still registered:$left; holders of the device nodes:"; sudo -n fuser -v /dev/nvidia[0-9]* 2>&1 | tail -n +2 | awk '{print $NF}' | sort | uniq -c | head; fi
  [ $i -eq 90 ] && { log "removal did not finish; stop the remaining holders and rerun"; exit 2; }
  sleep 2
done

healthy() {  # bdf -> 0 when nvidia-smi can query it and no reset is pending
  out=$(timeout 60 nvidia-smi -q -i "$1" 2>&1) || return 1
  echo "$out" | grep -qiE "Reset Required|ERR!|Unknown Error" && return 1
  return 0
}
rc=0
for b in $GPUS; do
  log "== bind $b"
  echo "$b" | sudo -n tee /sys/bus/pci/drivers/nvidia/bind >/dev/null 2>&1 || log "bind write failed"
  sleep 5
  if healthy "$b"; then log "$b healthy after bind"; continue; fi
  log "$b not healthy after bind (GSP did not come up) -> unbind, FLR via sysfs, bind again"
  echo "$b" | sudo -n tee /sys/bus/pci/drivers/nvidia/unbind >/dev/null 2>&1; sleep 3
  echo 1 | sudo -n tee /sys/bus/pci/devices/$b/reset >/dev/null 2>&1 || log "sysfs reset failed"; sleep 3
  echo "$b" | sudo -n tee /sys/bus/pci/drivers/nvidia/bind >/dev/null 2>&1; sleep 5
  if healthy "$b"; then log "$b healthy after reset+bind"; else log "$b STILL unhealthy"; rc=3; fi
done
sudo -n dmesg -T | grep -E "NVRM|nvidia-drm|nvidia 0000" | grep -vE "knvlink|nvAssert" | tail -6
timeout 60 nvidia-smi --query-gpu=index,pci.bus_id,memory.used,temperature.gpu --format=csv

if [ -x "$TORCH" ]; then
  log "== CUDA sanity: a context and a reduction on every visible GPU"
  timeout 120 "$TORCH" - <<'PY'
import torch
n = torch.cuda.device_count(); print("device_count", n)
for i in range(n):
    p = torch.cuda.get_device_properties(i)
    print(i, p.name, "ok" if torch.ones(1024, device=f"cuda:{i}").sum().item() == 1024 else "BAD")
PY
fi

log "== start everything again"
sudo -n systemctl start $DAEMONS
systemctl --user start $USER_UNITS
for i in $(seq 1 120); do
  ok=0; n=0
  for p in $PORTS; do n=$((n+1)); curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:$p/v1/models 2>/dev/null | grep -q "200\|401\|404" && ok=$((ok+1)); done
  log "services answering: $ok/$n"; [ $ok -eq $n ] && break; sleep 10
done
systemctl --user list-units $(for u in $USER_UNITS; do echo "$u.service"; done) --no-pager --no-legend
timeout 20 nvidia-smi --query-gpu=index,pci.bus_id,memory.used --format=csv,noheader
log "HOST-GPU-RECOVER-DONE rc=$rc"
exit $rc
