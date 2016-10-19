import ssl
import sys
import re
import argparse
import OpenSSL
import Crypto
from Crypto.PublicKey.RSA import RSAImplementation
import os
import socket
import traceback
import requests
from functools import wraps
import errno
import os
import signal
import datetime
import json
import keys_basic
from Queue import Queue
from threading import Thread, Lock
from collections import OrderedDict
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtensionOID
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from Crypto.PublicKey.RSA import RSAImplementation
import base64
import types
import struct
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div
import key_stats


def main():
    parser = argparse.ArgumentParser(description='SSL dump')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=None,
                        help='Number of threads to use for cert download')
    parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                        help='enables debug mode')
    parser.add_argument('-f', '--filter-org', dest='filter_org',
                        help='Filter out certificates issued with given organization - regex')
    parser.add_argument('files', nargs=argparse.ONE_OR_MORE, default=[],
                        help='file with ssl-dump json output')

    args = parser.parse_args()

    # Require input
    if len(args.files) == 0:
        parser.print_usage()
        sys.exit(1)

    cert_db = []

    # Read input files
    for fl in args.files:
        with open(fl, mode='r') as fh:
            data = fh.read()

            # Parse json out
            if '-----BEGIN JSON-----' in data:
                if '-----END JSON-----' not in data:
                    raise ValueError('BEGIN JSON present but END JSON not')
                match = re.search(r'-----BEGIN JSON-----(.+?)-----END JSON-----', data, re.MULTILINE | re.DOTALL)
                if match is None:
                    raise ValueError('Could not extract JSON')
                data = match.group(1)

            json_data = json.loads(data)
            for rec in json_data:
                cert_db.append(rec)

    # Filtering
    cert_db_old = cert_db
    cert_db = []
    re_org = None if args.filter_org is None else re.compile(args.filter_org, re.IGNORECASE)

    for cert in cert_db_old:
        org = cert['org']
        if org is None:
            org = ''

        if re_org is not None and re_org.match(org) is None:
            print('Organization filtered out %s' % org)
            continue
        cert_db.append(cert)

    print('Certificate database size %d' % len(cert_db))
    




# Launcher
if __name__ == "__main__":
    main()