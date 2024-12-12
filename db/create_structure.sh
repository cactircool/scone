#!/bin/bash

mkdir certs
cd certs
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 3650 -passout pass:password -subj "/C=US/ST=Texas/L=Frisco/O=scone/OU=dev/CN=VeryCommonName"

cd ..
touch .env
cat > .env <<EOF
SUPABASE_URL='<enter supabase url here>'
SUPABASE_KEY='<enter supabase key here>'
PASSPHRASE='password'
CA_URL='https://localhost:8080' # assuming this is where the CA will be hosted
EOF