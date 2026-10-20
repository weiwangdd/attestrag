#!/bin/bash
set -e
modprobe sev-guest && echo "sev-guest loaded"
ls -la /dev/sev-guest
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
ls -d /sys/kernel/config/tsm/report >/dev/null 2>&1 || modprobe tsm
ls -d /sys/kernel/config/tsm/report && echo "tsm report dir OK"
R=/sys/kernel/config/tsm/report/r1; rmdir $R 2>/dev/null || true; mkdir -p $R
head -c 64 /dev/urandom > /tmp/nonce.bin; cat /tmp/nonce.bin > $R/inblob
echo "provider: $(cat $R/provider)  generation: $(cat $R/generation)"
cat $R/outblob > /tmp/report.bin; ls -la /tmp/report.bin
cat $R/auxblob > /tmp/certs.bin 2>/dev/null && ls -la /tmp/certs.bin || echo "no auxblob"
python3 - <<'PY'
import struct
b=open("/tmp/report.bin","rb").read(); n=open("/tmp/nonce.bin","rb").read()
print("report size:", len(b))
print("version:", struct.unpack_from("<I",b,0)[0], " guest_svn:", struct.unpack_from("<I",b,4)[0])
print("policy: 0x%016x" % struct.unpack_from("<Q",b,8)[0])
print("vmpl:", struct.unpack_from("<I",b,0x30)[0], " signature_algo:", struct.unpack_from("<I",b,0x34)[0])
print("report_data == nonce:", b[0x50:0x90]==n)
print("measurement:", b[0x90:0xC0].hex())
print("host_data:", b[0xC0:0xE0].hex())
print("chip_id:", b[0x1A0:0x1E0].hex()[:32]+"...")
tcb=struct.unpack_from("<Q",b,0x180)[0]; print("current_tcb: boot=%d tee=%d snp=%d ucode=%d" % (tcb&0xff,(tcb>>8)&0xff,(tcb>>48)&0xff,(tcb>>56)&0xff))
print("signature r[:16]:", b[0x2A0:0x2B0].hex())
PY
