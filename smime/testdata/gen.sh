#!/bin/sh
# Generates the S/MIME test vectors with OpenSSL, an implementation
# independent from ours. Test PKI only: these keys protect nothing.
set -e
cd "$(dirname "$0")"

cat > ext.cnf <<'CNF'
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ica]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = emailProtection, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = emailProtection
subjectAltName = email:signer@example.com
certificatePolicies = 2.23.140.1.5.2.2
authorityInfoAccess = OCSP;URI:http://pki.test/ocsp
crlDistributionPoints = URI:http://pki.test/ica.crl
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[selfsigned]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = emailProtection
subjectAltName = email:signer@example.com
CNF

openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 7300 \
  -subj "/C=CH/O=Test PKI/CN=Test SMIME Root" -extensions root -config ext.cnf -sha256 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout ica.key -out ica.csr -subj "/C=CH/O=Test PKI/CN=Test SMIME ICA" 2>/dev/null
openssl x509 -req -in ica.csr -CA root.pem -CAkey root.key -CAcreateserial -out ica.pem -days 7000 \
  -extfile ext.cnf -extensions ica -sha256 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
  -subj "/C=CH/O=Example Org/organizationIdentifier=NTRCH-CHE-123.456.789/CN=Example Signer" 2>/dev/null
openssl x509 -req -in leaf.csr -CA ica.pem -CAkey ica.key -set_serial 4242 -out leaf.pem -days 6900 \
  -extfile ext.cnf -extensions leaf -sha256 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout self.key -out self.pem -days 6900 \
  -subj "/CN=Self Signed" -extensions selfsigned -config ext.cnf -sha256 2>/dev/null

printf 'Content-Type: text/plain; charset=utf-8\r\n\r\nPaiement de la facture 2026-17.\r\nMerci.\r\n' > content.txt
headers='From: Example Signer <signer@example.com>\r\nTo: user@example.org\r\nSubject: Facture\r\n'

# Detached (multipart/signed), definite lengths
{ printf "$headers"; openssl smime -sign -in content.txt -signer leaf.pem -inkey leaf.key -certfile ica.pem -binary -md sha256; } > detached.eml
# Detached, BER with indefinite lengths, as IncaMail
{ printf "$headers"
  printf 'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;\r\n\tboundary="b1"\r\n\r\n--b1\r\n'
  cat content.txt
  printf '\r\n--b1\r\nContent-Type: application/pkcs7-signature; name="smime.p7s"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
  openssl cms -sign -in content.txt -signer leaf.pem -inkey leaf.key -certfile ica.pem -binary -indef -outform DER -md sha256 | base64 -w 76 | sed 's/$/\r/'
  printf '\r\n--b1--\r\n'; } > ber.eml
# Opaque and streamed: BER, content in constructed octet strings
{ printf "$headers"; openssl cms -sign -nodetach -stream -in content.txt -signer leaf.pem -inkey leaf.key -certfile ica.pem -binary -md sha256 -outform SMIME; } > streamed.eml
# Opaque (application/pkcs7-mime)
{ printf "$headers"; openssl smime -sign -nodetach -in content.txt -signer leaf.pem -inkey leaf.key -certfile ica.pem -binary -md sha256; } > opaque.eml
# Self-signed certificate
{ printf "$headers"; openssl smime -sign -in content.txt -signer self.pem -inkey self.key -binary -md sha256; } > selfsigned.eml
# Encrypted
{ printf "$headers"; openssl smime -encrypt -aes256 -in content.txt leaf.pem; } > encrypted.eml

rm -f ext.cnf *.csr *.srl self.key leaf.key root.key
