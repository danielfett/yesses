#!/bin/bash

# RSA root certificate
openssl genrsa -out rsa_ca_key.pem 2048
openssl req -x509 -new -nodes -key rsa_ca_key.pem -out rsa_ca_cert.pem -days 365 -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=test.dev.intranet"

# ECDSA root certificate
openssl ecparam -out ecdsa_ca_key.pem -name prime256v1 -genkey
openssl req -x509 -new -nodes -key ecdsa_ca_key.pem -out ecdsa_ca_cert.pem -days 365 -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=test.dev.intranet"

# Certificate for the laravel server
openssl ecparam -out modern_key.pem -name prime256v1 -genkey
openssl req -new -key modern_key.pem -out modern_cert.csr -sha512 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=laravel.dev.intranet"
openssl x509 -req -in modern_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
  -extensions SAN \
  -extfile <(cat /etc/ssl/openssl.cnf \
    <(printf "\n[SAN]\nsubjectAltName=DNS:laravel.dev.intranet")) \
  -CAcreateserial -out modern_cert.pem -days 90 -sha512

# Certificate for the nginx server
openssl genrsa -out intermediate_key.pem 2048
openssl req -new -key intermediate_key.pem -out intermediate_cert.csr -sha256 \
  -subj "/C=TE/ST=TEST/L=TEST/O=TEST/CN=nginx.dev.intranet"
openssl x509 -req -in intermediate_cert.csr -CA ecdsa_ca_cert.pem -CAkey ecdsa_ca_key.pem \
  -extensions SAN \
  -extfile <(cat /etc/ssl/openssl.cnf \
    <(printf "\n[SAN]\nsubjectAltName=DNS:nginx.dev.intranet")) \
  -CAcreateserial -out intermediate_cert.pem -days 13 -sha256

c_rehash .
