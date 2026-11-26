#!/usr/bin/env bash
set -euo pipefail
umask 077
workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
cd "$workdir"

issue_certificate() {
  local key=$1 serial=$2 output=$3
  openssl req -new -x509 -key "$key" -subj /CN=mx1.example.test \
    -set_serial "$serial" -days 1 -sha256 -out "$output.pem"
}

get_digests() {
  local name=$1
  openssl x509 -in "$name.pem" -pubkey -noout > "$name.pub.pem"
  openssl pkey -pubin -in "$name.pub.pem" -outform DER -out "$name.spki.der"
  openssl x509 -in "$name.pem" -outform DER -out "$name.cert.der"
}

digest() {
  openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
}

matches() {
  local presented=$1
  shift
  local association
  for association in "$@"; do
    if [[ "$presented" == "$association" ]]; then
      return 0
    fi
  done
  return 1
}

checks=0
expect() {
  local expected=$1 label=$2 presented=$3
  shift 3
  local result=no-match
  if matches "$presented" "$@"; then
    result=match
  fi
  printf '%s: %s\n' "$label" "$result"
  if [[ "$result" != "$expected" ]]; then
    printf 'Expected %s\n' "$expected" >&2
    exit 1
  fi
  checks=$((checks + 1))
}

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out old.key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out new.key
issue_certificate old.key 1 old
issue_certificate old.key 2 renewed
issue_certificate new.key 3 new
for name in old renewed new; do
  get_digests "$name"
done

old_pin=$(digest old.spki.der)
renewed_pin=$(digest renewed.spki.der)
new_pin=$(digest new.spki.der)
old_cert_digest=$(digest old.cert.der)
renewed_cert_digest=$(digest renewed.cert.der)

expect match "Same key renewal, SPKI" "$renewed_pin" "$old_pin"
expect no-match "Same key renewal, whole certificate" "$renewed_cert_digest" "$old_cert_digest"
expect no-match "Old-only TLSA, B presented" "$new_pin" "$old_pin"
expect match "Overlap, A presented" "$old_pin" "$old_pin" "$new_pin"
expect match "Overlap, B presented" "$new_pin" "$old_pin" "$new_pin"
expect match "New-only TLSA, B presented" "$new_pin" "$new_pin"
expect no-match "New-only TLSA, A presented" "$old_pin" "$new_pin"
expect no-match "Certificate digest in an SPKI association" "$old_pin" "$old_cert_digest"
printf '%d/8 offline controls passed.\n' "$checks"
