#!/bin/bash
# h200: release /dev/nvidia3 so the pending unbind of GPU3 completes, then bring every GPU service back.
# Run as weiwang (sudo -n works). Order matters: nothing may reopen /dev/nvidia3 before the driver drops it.
set -u
USER_UNITS="vllm-deepseek vllm-embed vllm-qwen3vl30b"
echo "== $(date +%T) stop GPU daemons and all GPU services"
sudo -n systemctl stop nvidia-dcgm nvidia-persistenced
systemctl --user stop $USER_UNITS funasr-nano.service
for i in $(seq 1 60); do
  if ! sudo -n fuser -s /dev/nvidia3 2>/dev/null; then echo "$(date +%T) /dev/nvidia3 has no holders"; break; fi
  [ $i -eq 60 ] && { echo "holders remain:"; sudo -n fuser -v /dev/nvidia3 2>&1 | head; }
  sleep 2
done
echo "== wait for the nvidia driver to finish removing GPU3 and the cc script to bind vfio-pci"
for i in $(seq 1 60); do
  d=$(basename $(readlink /sys/bus/pci/devices/0000:44:00.0/driver 2>/dev/null) 2>/dev/null)
  [ "$d" = "vfio-pci" ] && { echo "$(date +%T) GPU3 bound to vfio-pci"; break; }
  sleep 3
done
ls -la /dev/vfio/ | tail -2; ls /dev/nvidia3 2>&1 | tail -1
echo "== $(date +%T) start everything again"
sudo -n systemctl start nvidia-persistenced nvidia-dcgm
systemctl --user start $USER_UNITS funasr-nano.service
for i in $(seq 1 120); do
  ok=0; for p in 8000 8001 8002 8004; do curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:$p/v1/models 2>/dev/null | grep -q "200\|401\|404" && ok=$((ok+1)); done
  echo "$(date +%T) services answering: $ok/4"; [ $ok -eq 4 ] && break; sleep 10
done
timeout 20 nvidia-smi --query-gpu=index,memory.used --format=csv,noheader
echo "RELEASE-CYCLE-DONE $(date +%T)"
