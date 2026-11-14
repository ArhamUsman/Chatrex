#!/bin/bash
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
    printf 'Usage: %s [OUTPUT_DIR] [--force]\n' "$0" >&2
    printf 'Default OUTPUT_DIR: certs\n' >&2
    printf 'Existing CA/server files are never overwritten unless --force is the second argument.\n' >&2
}

if (( $# > 2 )); then
    usage
    exit 2
fi

output_dir=${1:-certs}
force=false
if (( $# == 2 )); then
    if [[ $2 == --force ]]; then
        force=true
    else
        usage
        exit 2
    fi
fi
if [[ $output_dir == --force ]]; then
    usage
    exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
    printf 'Error: required command not found: openssl\n' >&2
    exit 1
fi
if ! command -v mktemp >/dev/null 2>&1; then
    printf 'Error: required command not found: mktemp\n' >&2
    exit 1
fi

mkdir -p -- "$output_dir"
ca_key="$output_dir/ca.key"
ca_cert="$output_dir/ca.crt"
server_key="$output_dir/server.key"
server_cert="$output_dir/server.crt"
serial_file="$output_dir/ca.srl"
output_files=("$ca_key" "$ca_cert" "$server_key" "$server_cert" "$serial_file")

if [[ $force == true ]]; then
    rm -f -- "${output_files[@]}"
else
    existing_files=()
    for file in "${output_files[@]}"; do
        if [[ -e $file || -L $file ]]; then
            existing_files+=("$file")
        fi
    done
    if (( ${#existing_files[@]} > 0 )); then
        printf 'Error: refusing to overwrite existing file(s):\n' >&2
        for file in "${existing_files[@]}"; do
            printf '  %s\n' "$file" >&2
        done
        printf 'Use %s %s --force to replace the CA and server certificate.\n' "$0" "$output_dir" >&2
        exit 1
    fi
fi

config_file=
csr_file=
cleanup_temporary_files() {
    if [[ -n $config_file ]]; then
        rm -f -- "$config_file"
    fi
    if [[ -n $csr_file ]]; then
        rm -f -- "$csr_file"
    fi
}
trap cleanup_temporary_files EXIT

config_file=$(mktemp "$output_dir/.openssl.cnf.XXXXXX")
csr_file=$(mktemp "$output_dir/.server.csr.XXXXXX")

cat >"$config_file" <<'EOF'
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = server_dn
x509_extensions = ca_ext
req_extensions = server_req_ext

[ server_dn ]
CN = chatrex-server

[ ca_ext ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[ server_req_ext ]
subjectAltName = @alt_names

[ server_ext ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 10.0.3.10
IP.2 = 127.0.0.1
DNS.1 = localhost
EOF

printf '[*] Generating a new local RSA-2048 CA.\n'
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -config "$config_file" -subj '/CN=Project-2-Local-CA' \
    -keyout "$ca_key" -out "$ca_cert"

printf '[*] Generating a new RSA-2048 server key and CSR.\n'
openssl req -new -newkey rsa:2048 -sha256 -nodes \
    -config "$config_file" -keyout "$server_key" -out "$csr_file"

printf '[*] Signing the server certificate with serverAuth and required SANs.\n'
openssl x509 -req -sha256 -days 365 -in "$csr_file" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAserial "$serial_file" -CAcreateserial \
    -extfile "$config_file" -extensions server_ext -out "$server_cert"

chmod 600 "$ca_key" "$server_key"
chmod 644 "$ca_cert" "$server_cert"

printf '[+] Server certificate SHA-256 fingerprint:\n'
openssl x509 -in "$server_cert" -noout -fingerprint -sha256
printf '[+] Server certificate SANs:\n'
openssl x509 -in "$server_cert" -noout -ext subjectAltName

printf '[+] Verifying serverAuth and identity 10.0.3.10:\n'
openssl verify -CAfile "$ca_cert" -purpose sslserver -verify_ip 10.0.3.10 "$server_cert"
printf '[+] Verifying serverAuth and identity localhost:\n'
openssl verify -CAfile "$ca_cert" -purpose sslserver -verify_hostname localhost "$server_cert"

printf '[+] Generated %s, %s, %s, and %s.\n' \
    "$ca_cert" "$ca_key" "$server_cert" "$server_key"
printf 'Private keys are lab-only; exclude ca.key and server.key from archives.\n'
