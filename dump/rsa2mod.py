import argparse
import re
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_pem_private_key(data, password=None, backend=None):
    return serialization.load_pem_private_key(data, None, get_backend(backend))


def load_pem_rsa_key_pycrypto(data, password=None):
    return RSA.importKey(data, passphrase=password)


# Parse command line arguments
parser = argparse.ArgumentParser(description='Extracts RSA modulus as a hexa string from PEM encoded RSA keys')
parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='PEM encoded RSA keys to process')
args = parser.parse_args()


for file_name in args.files:
    with open(file_name, 'r') as hnd:
        keys = hnd.read()

        # Key parsing
        parts = re.split('-{5,}BEGIN', keys)
        if len(parts) == 0:
            continue
        if len(parts[0]) == 0:
            parts.pop(0)
        keys = ['-----BEGIN'+x for x in parts]

        for key in keys:
            t = load_pem_rsa_key_pycrypto(key)
            print('%x' % t.n)


