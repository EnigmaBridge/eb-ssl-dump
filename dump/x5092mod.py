#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import re
import sys
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
parser = argparse.ArgumentParser(description='Extracts RSA modulus as a hexa string from PEM/DER encoded X509 certificates')
parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                    help='PEM/DER encoded X509 certificate files to process')
parser.add_argument('--pem', dest='pem', default=False, action='store_const', const=True,
                    help='Force PEM format')
parser.add_argument('--der', dest='der', default=False, action='store_const', const=True,
                    help='Force DER format')
parser.add_argument('--exp', dest='exponent', default=False, action='store_const', const=True,
                    help='Print also public exponent')
args = parser.parse_args()

for file_name in args.files:
    with open(file_name, 'rb') as hnd:
        crt = hnd.read()
        is_pem = file_name.endswith('.pem') or crt.startswith('-----BEGIN')

        if is_pem or args.pem:
            parts = re.split('-{5,}BEGIN', crt)
            if len(parts) == 0:
                continue
            if len(parts[0]) == 0:
                parts.pop(0)
            crt_arr = ['-----BEGIN'+x for x in parts]

            for key in crt_arr:
                try:
                    x509 = load_pem_x509_certificate(key, get_backend())
                    print_mod_hex(x509, print_e=args.exponent)
                except Exception as e:
                    traceback.print_exc()
                    sys.stderr.write('Exception in parsing key: %s\n' % e)

        if not is_pem or args.der:
            try:
                x509 = load_der_x509_certificate(crt, get_backend())
                print_mod_hex(x509, print_e=args.exponent)
            except Exception as e:
                traceback.print_exc()
                sys.stderr.write('Exception in parsing key: %s\n' % e)


