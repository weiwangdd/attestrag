set -e
cd ~/attest
echo "=== 1. request report (vmpl 0, random nonce) ==="
sudo ./snpguest report report.bin request.bin --random --vmpl 0
sudo chown ubuntu report.bin request.bin; ls -la report.bin request.bin
echo "=== 2. fetch ARK/ASK from AMD KDS ==="
rm -rf certs && mkdir certs
./snpguest fetch ca pem certs genoa
echo "=== 3. fetch VCEK for this chip/TCB ==="
./snpguest fetch vcek pem certs report.bin
ls -la certs
echo "=== 4. verify cert chain (ARK -> ASK -> VCEK) ==="
./snpguest verify certs certs
echo "=== 5. verify report signature with VCEK ==="
./snpguest verify attestation certs report.bin
echo "=== 6. report summary ==="
./snpguest display report report.bin | grep -E -A1 -i '^(Version|Guest SVN|Policy|Measurement|Report Data|Host Data|Reported TCB|Current TCB|Signature Algo|Platform Info|VMPL)' | grep -v '^--$' | head -40
echo "=== 7. VCEK subject / issuer ==="
openssl x509 -in certs/vcek.pem -noout -subject -issuer -dates 2>/dev/null || true
