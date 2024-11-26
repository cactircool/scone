#!/bin/bash

CERT_DIR_PREFIX='src/certs'

mkdir $CERT_DIR_PREFIX

openssl genrsa -out $CERT_DIR_PREFIX/server-key.pem 2048
openssl req -new -key $CERT_DIR_PREFIX/server-key.pem -out $CERT_DIR_PREFIX/server-csr.pem
openssl x509 -req -in $CERT_DIR_PREFIX/server-csr.pem -signkey $CERT_DIR_PREFIX/server-key.pem -out $CERT_DIR_PREFIX/server-cert.pem