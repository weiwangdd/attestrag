set -e
mkdir -p ~/attest && cd ~/attest
[ -x snpguest ] || { curl -sSL -o snpguest https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest && chmod +x snpguest; }
./snpguest --version
echo "=== report --help ==="; ./snpguest report --help 2>&1 | sed -n '1,14p'
echo "=== fetch ca --help ==="; ./snpguest fetch ca --help 2>&1 | sed -n '1,16p'
echo "=== fetch vcek --help ==="; ./snpguest fetch vcek --help 2>&1 | sed -n '1,14p'
echo "=== verify attestation --help ==="; ./snpguest verify attestation --help 2>&1 | sed -n '1,10p'
