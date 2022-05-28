#!/bin/sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

host=$1

wd=`dirname $0`

pushd $wd > /dev/null

# 0. Do a cleanup
rm -rf certificate.pem fullchain.pem issuer.pem

# 1. get server cert
echo "[+] Getting server certificate"
openssl s_client -connect ${host}:443 < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' > certificate.pem
if ! [[ -s certificate.pem ]]; then
    echo "[-] No certificate for provided host. Exiting..."
    exit 1
fi

# 2. get certificate chain
echo "[+] Getting certificate chain"
openssl s_client -showcerts -connect ${host}:443 < /dev/null 2>&1 |  sed -n '/-----BEGIN/,/-----END/p' > fullchain.pem 

# 3. extract issuer certs 
echo "[+] Extracting issuer certs"
diff fullchain.pem certificate.pem | tail +1 | sed 's/^< //g' > issuer.pem 

# 4. extract ocsp uri 
echo "[+] Extracting OCSP URI"
ocsp_uri=`openssl x509 -noout -ocsp_uri -in certificate.pem`
ocsp_host=`echo ${ocsp_uri} | cut -d'/' -f3`
echo "[*] Got $ocsp_uri"

# 5. verify with ocsp
echo "[+] Verifying"
openssl ocsp -issuer issuer.pem -cert certificate.pem -text -url ${ocsp_uri} -header "HOST" "${ocsp_host}"

popd > /dev/null
