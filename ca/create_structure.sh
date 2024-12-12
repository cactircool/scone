#!/bin/bash

mkdir certs
mkdir certs/https certs/radius

echo 'Fill certs/radius with your ca.pem and ca.key file used in freeradius'
echo "I'll fill certs/https with root signed certs, replace them with a CA signed set when available"

cd certs/https
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 3650 -passout pass:password -subj "/C=US/ST=Texas/L=Frisco/O=scone/OU=dev/CN=VeryCommonName"

cd ../..

touch .env
cat > .env <<EOF
CERTS_DIR="../certs"
HTTPS_CERTS_DIR="\$CERTS_DIR/https"
RADIUS_CERTS_DIR="\$CERTS_DIR/radius"

HTTPS_SERVER_CRT="\$HTTPS_CERTS_DIR/server.crt"
HTTPS_SERVER_KEY="\$HTTPS_CERTS_DIR/server.key"
HTTPS_CERTS_PASSPHRASE="password"

RADIUS_CA_PEM="\$RADIUS_CERTS_DIR/ca.pem"
RADIUS_CA_KEY="\$RADIUS_CERTS_DIR/ca.key"
EOF