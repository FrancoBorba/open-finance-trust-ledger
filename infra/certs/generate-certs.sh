#!/usr/bin/env bash
set -e

# Prevent Git Bash (MSYS2/MINGW64) on Windows from converting /C=BR into Windows file paths
export MSYS_NO_PATHCONV=1

# Ensure all certificate artifacts are generated inside infra/certs
cd "$(dirname "$0")"

echo "=== [1/3] Generating Root Certificate Authority (Mock ICP-Brasil Chain V10) ==="
cat > ca.cnf <<EOF
[req]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = ca_dn
x509_extensions = v3_ca

[ca_dn]
C = BR
O = ICP-Brasil
OU = Mock Certificate Authority V10
CN = OFB Mock Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,cRLSign,keyCertSign
EOF

openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -config ca.cnf

echo "=== [2/3] Generating Server Certificate (ICP WEB SSL Profile) ==="
cat > server.cnf <<EOF
[req]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = server_dn
req_extensions = server_ext

[server_dn]
C = BR
ST = SP
L = Sao Paulo
O = Open Finance Trust Ledger Server
CN = localhost

[server_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = trust-gateway
DNS.3 = bank1-mock
DNS.4 = bank2-mock
DNS.5 = bank3-mock
IP.1 = 127.0.0.1
EOF

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server.cnf -extensions server_ext

echo "=== [3/3] Generating Client Transport Certificate (OFB Chain V10 Post-Aug/2022) ==="
# Follows the OpenSSL template from Open Finance Brasil Certificate Standards Appendix
# Note: OpenSSL 3.x natively includes OID 2.5.4.97 (organizationIdentifier)
cat > client.cnf <<EOF
[req]
default_bits = 2048
default_md = sha256
prompt = no
string_mask = nombstr
distinguished_name = client_distinguished_name
req_extensions = req_cert_extensions

[client_distinguished_name]
businessCategory = Private Organization
jurisdictionCountryName = BR
serialNumber = 43142666000197
countryName = BR
organizationName = SME Cash Management Receptor S.A.
stateOrProvinceName = SP
localityName = Sao Paulo
organizationIdentifier = OFBBR-d7384bd0-842f-43c5-be02-9d2b2d5efc2c
UID = bc97b8f0-cae0-4f2f-9978-d93f0e56a833
commonName = gateway.tpp.openfinance.local

[req_cert_extensions]
basicConstraints = CA:FALSE
subjectAltName = @alt_name
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth

[alt_name]
DNS.1 = gateway.tpp.openfinance.local
DNS.2 = localhost
EOF

openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -config client.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256 -extfile client.cnf -extensions req_cert_extensions

# Clean up temporary signing requests (.csr), configs (.cnf), and serial files (.srl)
rm -f *.csr *.cnf *.srl

echo "=== Success! All 6 PKI files (.key and .crt) generated in infra/certs/ ==="