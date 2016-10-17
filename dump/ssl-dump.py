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
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from Crypto.PublicKey.RSA import RSAImplementation

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
parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='file with domains to process')

args = parser.parse_args()

#
# Domains array preparation
#
domains = []
for fl in args.files:
    with open(fl, mode='r') as fh:
        for line in fh.readlines():
            parts = [x.strip() for x in line.split()]
            for part in parts:
                if part is None or len(part) == 0:
                    continue
                domains.append(part)

if args.domains is not None and len(args.domains) > 0:
    for d in args.domains:
        domains.append(d)

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
        pass
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


#
# Main
#
print('Domains to process: ')
print(domains)

requests.packages.urllib3.disable_warnings()
cns = []
for d in domains:
    d = d.strip()
    d = d.replace('http://', '')
    d = d.replace('https://', '')
    d = d.replace('/', '')
    if len(d) == 0:
        continue
    try:
        with timeout(seconds=3):
            resp = requests.get('https://'+d, verify=False)
            cert = resp.peercert
            certex = resp.peercertex

            # cert = ssl.get_server_certificate((d, 443))
            # if cert is None:
            #     continue

            x509 = load_x509(str(cert))
            # print x509.public_key()
            # print x509.public_bytes()
            # print x509.subject
            print cert
            cns.append(get_cn(certex))

    except KeyboardInterrupt:
        break
    except TimeoutError:
        continue
    except AttributeError:
        continue
    except:
        sys.stderr.write('Domain [%s]\n' % d)
        traceback.print_exc()
        continue

print cns



