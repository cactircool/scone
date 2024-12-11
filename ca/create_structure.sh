#!/bin/bash

mkdir certs
mkdir certs/https certs/radius

echo 'Fill certs/radius with your ca.pem and ca.key file used in freeradius'
echo "I'll fill certs/https with root signed certs, replace them with a CA signed set when available"

cd certs/https
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 3650 -passout pass:YourSecurePassphrase "/C=US/ST=Texas/L=Frisco/O=scone/OU=dev/CN=VeryCommonName"