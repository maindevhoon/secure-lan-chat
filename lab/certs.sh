#!/bin/sh
set -eu

keys=${1:-/keys}
trust=${2:-/trust}
lan_ip=${CHAT_LAN_IP:-}
if [ -n "$lan_ip" ]; then
    python -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "$lan_ip"
fi
san="DNS:server,DNS:localhost,IP:127.0.0.1"
if [ -n "$lan_ip" ] && [ "$lan_ip" != "127.0.0.1" ]; then
    san="$san,IP:$lan_ip"
fi

mkdir -p "$keys" "$trust"
umask 077
if [ ! -s "$keys"/server.key ] || [ ! -s "$keys"/server.crt ] ||
   [ "$(cat "$keys"/san 2>/dev/null || true)" != "$san" ] ||
   ! openssl x509 -in "$keys"/server.crt -noout -checkend 86400 >/dev/null; then
    temp=$(mktemp -d "$keys/.cert.XXXXXX")
    trap 'rm -rf "$temp"' EXIT
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
        -subj "/CN=Secure LAN Chat" -addext "subjectAltName=$san" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=serverAuth" \
        -keyout "$temp/server.key" -out "$temp/server.crt"
    if [ "$(id -u)" -eq 0 ]; then
        chown 10001:10001 "$temp/server.key"
    fi
    chmod 644 "$temp/server.crt"
    mv "$temp/server.key" "$temp/server.crt" "$keys"/
    printf '%s\n' "$san" > "$keys"/san
fi
cp "$keys"/server.crt "$trust"/.server.crt.tmp
chmod 644 "$trust"/.server.crt.tmp
mv "$trust"/.server.crt.tmp "$trust"/server.crt
openssl x509 -in "$trust"/server.crt -noout -fingerprint -sha256
