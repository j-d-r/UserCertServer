#!/bin/sh

CA_VALIDITY = 3650
CA_KEY_SIZE = 4096

mkdir -p "CA/private" "CA/newcerts"
chmod 700 "CA/private"
touch "CA/index.txt"
touch "CA/index.txt.attr"
echo 01 > "CA/serial"

openssl genrsa -des3 -out "CA/private/cakey.pem" $CA_KEY_SIZE
openssl req -new -x509 -days $CA_VALIDITY -key "CA/private/cakey.pem" -out "CA/cacert.pem"
