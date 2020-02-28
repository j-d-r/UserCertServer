#!/usr/bin/env python3

# Copyright (C) 2020 Julien Dusser
# http://github.com/j-d-r/UserCertServer
#
# SPDX-License-Identifier: GPL-3.0-or-later

""" Small Python HTTP server to generate client certificates for user
authentication.

Support deprecated SPKAC for Firefox Mobile as there is no other way to store
client certificate.

Support PKCS#12 export of client certificate with key as at least a
10-character password is given at boot.
"""

import base64 as b64
import datetime as dt
import getpass as gp
import http.server
import sys
import time as tm
import urllib.parse as up

import cryptography.x509 as x509
import cryptography.hazmat.backends as bk
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.serialization as sr

import OpenSSL.crypto as c

import pyasn1.codec.der.decoder as asn1

# used in NetscapeSPKI workaround
from OpenSSL._util import (ffi as _ffi, lib as _lib)

CERT_VALIDITY = 365
CERT_KEY_SIZE = 2048
CERT_RSA_EXP = 65537
CA_LOGFILE = 'CA/log.txt'
CA_CERTFILE = 'CA/cacert.pem'
CA_KEYFILE = 'CA/private/cakey.pem'
TEMPLATE = """<!DOCTYPE html>
<html>
<link id="favicon" rel="shortcut icon" type="image/png" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgAgMAAAAOFJJnAAAACVBMVEUAAGeAINAbjSZ4BDaEAAAAAXRSTlMAQObYZgAAAEZJREFUGNNjYGBgEA1hAAPG0FAHMIM1NDQAzBANYIXIhYIREAC5omC1IAZINSNQJSv5jFVgQDRjhRaUsYALnQGXIoZBtKUAOyxMQduxajcAAAAASUVORK5CYII=">
<body style="text-align: center;">
    <h1>Generate Certificate</h1>
    <h2 style="color: red">{error}</h2>
    <form method="post">
        <keygen name="pubkey" keyparam="high" challenge="{chall}"
        alt="SPKAC unsupported" title="key strength" /><br /><br />
        <input type="hidden" name="challenge" value="{chall}" />
        <input type="text" name="username" placeholder="enter username"
        title="certificate username" /><br /><br />
        <input type="submit" name="createcert" value="Generate" />
    </form>
</body>
</html>"""


class Param:
    """Store here globals as BaseHTTPRequestHandler is stateless."""
    pass


p = Param()


def get_challenge_nspki(spkac_str):
    """Extract challenge from SPKAC string."""
    try:
        seq, rest = asn1.decode(b64.b64decode(spkac_str))
    except Exception as err:
        raise Exception('SPKAC decode failed: {}'.format(err))
    if rest or len(seq) != 3 \
            or len(seq[0]) != 2 \
            or len(seq[1]) not in (1, 2) \
            or len(seq[1]) == 2 and seq[1][1]:
        raise Exception('Unknown SPKAC data format')
    return seq[0][1]


class NetscapeSPKINew(c.NetscapeSPKI):
    """Workaround to initialize NetscapeSPKI."""
    def __init__(self, spkac_str=None):
        if spkac_str is not None:
            self._spki = NetscapeSPKINew.b64_decode(spkac_str)._spki
        else:
            spki = _lib.NETSCAPE_SPKI_new()
            self._spki = _ffi.gc(spki, _lib.NETSCAPE_SPKI_free)

    @classmethod
    def b64_decode(cls, spkac_str):
        """
        Construct a NetscapeSPKI from spkac base64 string

        :param spkac_str: base64 encoded string
        """

        new = cls()
        arg = _ffi.new('char[]', spkac_str)
        spki = _lib.NETSCAPE_SPKI_b64_decode(arg, -1)
        if spki == _ffi.NULL:
            raise ValueError('Invalid SPKAC string')
        new._spki = _ffi.gc(spki, _lib.NETSCAPE_SPKI_free)
        return new


c.NetscapeSPKI = NetscapeSPKINew


class Server(http.server.BaseHTTPRequestHandler):
    """HTTP server request handler."""

    def _set_headers(self, code=200):
        """Send common headers."""
        self.send_response(code)
        self.send_header('Content-type', 'text/html; charset=UTF-8')
        self.end_headers()

    def do_GET(self):
        """Respond to GET request by displaying form."""
        if self.path != '/':
            self._set_headers(404)
            return

        p.challenge = x509.random_serial_number()
        self._set_headers()
        self.wfile.write(TEMPLATE.format(error='', chall=p.challenge).encode())

    def do_HEAD(self):
        """Respond to HEAD request."""
        self._set_headers()

    def do_POST(self):
        """Get parameters from client, generate and send client cert."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        req = {}
        for data in up.parse_qsl(post_data):
            req[data[0].decode()] = data[1].decode()

        pubkey = None
        try:
            if 'username' not in req or 'challenge' not in req:
                raise Exception('Missing username')

            username = req['username']
            if not username.isalnum():
                raise Exception('Bad username')

            if p.challenge != int(req['challenge']):
                raise Exception('Bad challenge')

            if 'pubkey' in req:
                pubkey = ''.join([x for x in req['pubkey'] if x not in '\t\n\r\0\x0B'])
                cert = gen_cert_spkac(self.client_address[0], pubkey, username)
                self.send_response(200)
                self.send_header('Content-type', 'application/x-x509-user-cert')
            else:
                if not p.export_pass:
                    raise Exception('You must set an export passord when launching server')

                cert = gen_cert_p12(self.client_address[0], username)
                self.send_response(200)
                self.send_header('Content-type', 'application/x-pkcs12')
                self.send_header('Content-Disposition', 'inline; filename="{}.p12"'.format(username))

            p.challenge = x509.random_serial_number()
            self.end_headers()
            self.wfile.write(cert)

        except Exception as err:
            self._set_headers(422)
            p.challenge = x509.random_serial_number()
            self.wfile.write(TEMPLATE.format(error=err, chall=p.challenge).encode())
            return


def gen_cert_p12(addr, username):
    """Generate a PKCS#12 certificate and RSA key."""
    private_key = rsa.generate_private_key(CERT_RSA_EXP, CERT_KEY_SIZE, bk.default_backend())
    cert = gen_cert(private_key.public_key(), username)

    p12 = c.PKCS12()
    p12.set_certificate(c.X509.from_cryptography(cert))
    p12.set_ca_certificates([c.X509.from_cryptography(p.cacert), ])
    p12.set_privatekey(c.PKey.from_cryptography_key(private_key))
    p12str = p12.export(passphrase=p.export_pass)

    with open(CA_LOGFILE, 'ab') as logf:
        logf.write(('{} {} {} PKCS12\n'.format(tm.time(), addr, username)).encode())
        logf.write(cert.public_bytes(sr.Encoding.PEM))

    return p12str


def gen_cert_spkac(addr, spkac_str, username):
    """Generate a certificate from SPKAC string."""
    spki = c.NetscapeSPKI(spkac_str.encode())

    if p.challenge != int(get_challenge_nspki(spkac_str.encode())):
        raise Exception('Bad challenge')

    if not spki.verify(spki.get_pubkey()):
        raise Exception('Bad SPKAC pubkey')

    pkey = spki.get_pubkey().to_cryptography_key()
    cert_pem = gen_cert(pkey, username).public_bytes(sr.Encoding.PEM)

    with open(CA_LOGFILE, 'ab') as logf:
        logf.write(('{} {} {} SPKAC\n'.format(tm.time(), addr, username)).encode())
        logf.write(cert_pem)

    return cert_pem


def gen_cert(pkey, username):
    """Generate client certificate."""
    bld = x509.CertificateBuilder()
    bld = bld.subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, username), ]))
    bld = bld.issuer_name(p.cacert.subject)
    bld = bld.not_valid_before(dt.datetime.today() - dt.timedelta(days=1))
    bld = bld.not_valid_after(dt.datetime.today() + dt.timedelta(days=CERT_VALIDITY))
    bld = bld.serial_number(x509.random_serial_number())
    bld = bld.public_key(pkey)
    bld = bld.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    bld = bld.add_extension(x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=True)
    bld = bld.add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                            critical=True)
    cert = bld.sign(p.cakey, hashes.SHA256(), bk.default_backend())
    return cert


def run(server_class=http.server.HTTPServer, handler_class=Server, port=8000):
    """Run HTTP server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting HTTP Server on port {}'.format(port))
    httpd.serve_forever()


def print_ip():
    try:
        import netifaces

        PROTO = netifaces.AF_INET   # We want only IPv4, for now at least

        # Get list of network interfaces
        ifaces = netifaces.interfaces()

        # Get addresses for each interface
        if_addrs = [(netifaces.ifaddresses(iface), iface) for iface in ifaces]

        # Filter for only IPv4 addresses
        if_inet_addrs = [(tup[0][PROTO], tup[1]) for tup in if_addrs if PROTO in tup[0]]

        for tup in if_inet_addrs:
            for s in tup[0]:
                if 'addr' in s:
                    print("Listening on %s (%s)" % (s['addr'], tup[1]))

    except ImportError:
        pass


def main():
    print_ip()
    p.ca_pass = gp.getpass(prompt='CA Key Password: ', stream=None).encode()
    if not p.ca_pass:
        p.ca_pass = None

    try:
        with open(CA_CERTFILE, 'rb') as certf:
            p.cacert = x509.load_pem_x509_certificate(certf.read(), bk.default_backend())

        with open(CA_KEYFILE, 'rb') as keyf:
            p.cakey = sr.load_pem_private_key(keyf.read(), p.ca_pass, bk.default_backend())

    except Exception as err:
        print('Failed to load CA: {}'.format(err), file=sys.stderr)
        sys.exit(-1)

    p.export_pass = gp.getpass(prompt='P12 export Password: ', stream=None).encode()
    if len(p.export_pass) < 10:
        print('Warning P12 export disabled. Give at least 10 characters')
        p.export_pass = None

    p.challenge = x509.random_serial_number()
    if len(sys.argv) == 2:
        run(port=int(sys.argv[1]))
    else:
        run()


if __name__ == '__main__':
    main()
