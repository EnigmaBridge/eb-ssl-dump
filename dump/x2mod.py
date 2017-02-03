#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import re
import sys
import base64
import traceback
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def print_mod_hex(x509, print_e=False):
    if x509 is None:
        return
    pub = x509.public_key()
    if not isinstance(pub, RSAPublicKey):
        sys.stderr.write('non-RSA public key\n')
        return

    pubnum = x509.public_key().public_numbers()
    if print_e:
        print('%x %x' % (pubnum.n, pubnum.e))
    else:
        print('%x' % pubnum.n)


# Parse command line arguments
parser = argparse.ArgumentParser(description='Extracts RSA modulus as a hexa string from files')
parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                    help='X509 certificates to process')
parser.add_argument('--exp', dest='exponent', default=False, action='store_const', const=True,
                    help='Print also public exponent')
args = parser.parse_args()

for file_name in args.files:
    reg = re.compile(r'::\s*([0-9a-zA-Z+/=\s\t\r\n]{20,})$', re.MULTILINE | re.DOTALL)

    with open(file_name, 'r') as hnd:
        data = hnd.read()
        num_certs = data.count('userCertificate;')
        matches = re.findall(reg, data)

        num_certs_found = 0
        for idx, match in enumerate(matches):
            match = re.sub('[\r\t\n\s]', '', match)
            try:
                bindata = base64.b64decode(match)
                x509 = load_der_x509_certificate(bindata, get_backend())
                print_mod_hex(x509, print_e=args.exponent)
                num_certs_found += 1

            except Exception as e:
                traceback.print_exc()
                sys.stderr.write('Exception in parsing key idx %d: %s\n' % (idx, e))

        sys.stderr.write('Finished, #of certs: %d, # of certs found: %d\n' % (num_certs, num_certs_found))

