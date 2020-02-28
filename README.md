# UserCertServer

## Description

Small Python HTTP server to generate client certificates for user
authentication.

Support deprecated SPKAC for Firefox Mobile as there is no other way to store
client certificate.

Support PKCS#12 export of client certificate with key as at least a
10-character password is given at boot.

## Requirement

- pyopenssl
- cryptography
- pyasn1

Tested with python-3.6, pyopenssl-19.0.0, cryptography-2.5 and pyasn1-0.4.5.

## Usage

Build CA certificate and RSA key:

    ./create-CA.sh

Start python webserver (port 8000):

    python3 ./server.py

## Limitations

- You must have a secure connection beetwen browser and server, e.g: ssh tunnel, VPN, local server, ...
- Poor webserver, does not support multiple clients at once. Chrome can keep connection opened preventing other browsers.
- Don't forget to turn it off, read log in CA/log.txt
- NO WARRANTY OF ANY KIND, USE IT AT YOUR OWN RISK.
