import ssl
import sys
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
from Queue import Queue
from threading import Thread
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

#
# Misc helpers
#
def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    return load_pem_x509_certificate(data, get_backend(backend))


#
# Arguments
#
parser = argparse.ArgumentParser(description='SSL dump')
parser.add_argument('-d',   dest='domains', nargs=argparse.ZERO_OR_MORE,
                            help='domain', default=[])
parser.add_argument('--bw', dest='bw', nargs=argparse.ZERO_OR_MORE, default=[])
parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                            help='enables debug mode')
parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='file with domains to process')

args = parser.parse_args()

#
# Domains array preparation
#
domains = set([])
for fl in args.files:
    with open(fl, mode='r') as fh:
        for line in fh.readlines():
            parts = [x.strip() for x in line.split()]
            for part in parts:
                if part is None or len(part) == 0:
                    continue
                domains.add(part)

if args.domains is not None and len(args.domains) > 0:
    for d in args.domains:
        domains.add(d)

# CSV files, first is domain, separator is ','
if args.bw is not None:
    for bwf in args.bw:
        with open(bwf, mode='r') as fh:
            for line in fh.readlines():
                if line is None or len(line)==0:
                    continue
                parts = [x.strip() for x in line.split(',')]
                if len(parts) < 2:
                    continue
                domains.add(parts[0])

if len(domains) == 0:
    print 'No domains given'
    sys.exit(1)

#
# Certificate loading
#
HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__


def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        cert_ex = self._connection.sock.getpeercert()
        cert_der = self._connection.sock.getpeercert(True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        self.peercert = cert_pem
        self.peercertex = cert_ex
    except AttributeError:
        pass


HTTPResponse.__init__ = new_HTTPResponse__init__
HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response


def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercert = resp.peercert
        response.peercertex = resp.peercertex
    except AttributeError:
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response

#
# Processing
#
def get_cn(obj):
    """Accepts requests cert"""
    if obj is None:
        return None
    if 'subject' not in obj:
        return None
    try:
        sub = obj['subject'][0]
        for x in sub:
            if x[0] == 'commonName':
                return x[1]
    except:
        if args.debug:
            traceback.print_exc()
    return None


def get_alts(obj):
    """Accepts requests cert"""
    if obj is None:
        return []
    if 'subjectAltName' not in obj:
        return []
    try:
        buf = []
        for x in obj['subjectAltName']:
            if x[0] == 'DNS':
                buf.append(x[1])

        return buf
    except:
        if args.debug:
            traceback.print_exc()
    return []


def get_dn_part(subject, oid=None):
    if subject is None:
        return None
    if oid is None:
        raise ValueError('Disobey wont be tolerated')
    try:
        for sub in subject:
            if oid is not None and sub.oid == oid:
                return sub.value
    except:
        if args.debug:
            traceback.print_exc()
    return None


class TimeoutError(Exception):
    pass


class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)


def unix_time_millis(dt):
    return (dt - epoch).total_seconds()

#
# Main
#
domains_tmp = domains
domains = set([])
for d in domains_tmp:
    d = d.strip()
    d = d.replace('http://', '')
    d = d.replace('https://', '')
    d = d.replace('/', '')
    if len(d) == 0:
        continue
    domains.add(d)

    # explode with www. prefix
    # if not d.startswith('www.'):
    #     domains.add('www.' + d)

print('Domains to process: ')
print(domains)

requests.packages.urllib3.disable_warnings()
cns = []
pubkey_set = set()
cert_set = set()
utc_now = datetime.datetime.utcnow()
epoch = datetime.datetime.utcfromtimestamp(0)

# Multithreading init
num_threads = max(16, len(domains))
queue = Queue()
for d in domains:
    queue.put(d)


def process_domain(d):
    try:
        resp = requests.get('https://'+d, verify=False, timeout=5)
        cert = resp.peercert
        certex = resp.peercertex
        cd = OrderedDict()

        cd['cn'] = get_cn(certex)
        cd['alts'] = get_alts(certex)

        x509 = load_x509(str(cert))
        subject = x509.subject
        issuer = x509.issuer

        # generic
        cd['version'] = str(x509.version)
        cd['serial'] = x509.serial
        cd['not_before'] = unix_time_millis(x509.not_valid_before)
        cd['not_before_fmt'] = x509.not_valid_before.isoformat()
        cd['not_after'] = unix_time_millis(x509.not_valid_after)
        cd['not_after_fmt'] = x509.not_valid_after.isoformat()

        # Subject
        cd['loc'] = get_dn_part(subject, NameOID.LOCALITY_NAME)
        cd['org'] = get_dn_part(subject, NameOID.ORGANIZATION_NAME)
        cd['orgunit'] = get_dn_part(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)

        # Issuer
        cd['issuer_cn'] = get_dn_part(issuer, NameOID.COMMON_NAME)
        cd['issuer_loc'] = get_dn_part(issuer, NameOID.LOCALITY_NAME)
        cd['issuer_org'] = get_dn_part(issuer, NameOID.ORGANIZATION_NAME)
        cd['issuer_orgunit'] = get_dn_part(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)

        # Signature
        cd['sig_alg'] = x509.signature_hash_algorithm.name

        # pubkey
        pk = OrderedDict()
        n = x509.public_key().public_numbers().n
        pk['pem'] = x509.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pk['n'] = n
        pk['n_hex'] = base64.b16encode(long_to_bytes(n))
        pk['e'] = x509.public_key().public_numbers().e
        pk['e_hex'] = base64.b16encode(long_to_bytes(x509.public_key().public_numbers().e))

        # pubkey analysis
        # analysis: top 2 bytes, lower 1 byte, modulo 3..40, length
        buff = long_to_bytes(n)
        pk['len'] = len(buff)
        pk['hi2'] = base64.b16encode(buff[-2:])
        pk['lo2'] = base64.b16encode(buff[0:2])

        mmod = []
        for ix in range(3,41,2):
            mres = n % ix
            mmod.append({'i':ix, 'res':mres})
        pk['mmod'] = mmod

        cd['pubkey'] = pk

        # cert in the pem
        cd['cert'] = x509.public_bytes(Encoding.PEM)

        # not json serializable
        #cd['pubkey'] = x509.public_key()

        # cert = ssl.get_server_certificate((d, 443))
        # if cert is None:
        #     continue

        return cd

    except KeyboardInterrupt:
        return None
    except TimeoutError:
        if args.debug:
            traceback.print_exc()
        return None
    except AttributeError:
        if args.debug:
            traceback.print_exc()
        return None
    except:
        sys.stderr.write('Domain [%s]\n' % d)
        traceback.print_exc()
        return None


def domain_processed(res):
    if res is None:
        return

    cns.append(res)
    cert_set.add(res['cert'])
    pubkey_set.add(res['pubkey']['pem'])
    print(res['cert'])


def worker_main(queue):
    while not queue.empty():
        d = queue.get()
        res = process_domain(d)
        domain_processed(res)


workers = []
for i in range(num_threads):
    worker = Thread(target=worker_main, args=(queue,))
    worker.setDaemon(True)
    worker.start()
    workers.append(worker)

for worker in workers:
    worker.join()

print json.dumps(cns, indent=4)

print('Domains count: %d' % len(domains))
print('Unique certificates: %d' % len(cert_set))
print('Unique pubkeys: %d' % len(pubkey_set))

