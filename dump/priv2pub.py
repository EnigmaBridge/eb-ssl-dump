import os
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey.RSA import RSAImplementation


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_pem_private_key(data, password=None, backend=None):
    return serialization.load_pem_private_key(data, None, get_backend(backend))


def load_pem_private_key_pycrypto(data, password=None):
    return RSA.importKey(data, passphrase=password)

rsa = RSAImplementation()
base_path = '/Users/dusanklinec/Downloads/EC2_keys'

for i in range(0, 200):
    file_name = os.path.join(base_path, 'test%d.pem' % i)
    if not os.path.exists(file_name):
        continue

    with open(file_name, 'r') as hnd:
        key = hnd.read()
        t = load_pem_private_key_pycrypto(key)

        rsa_key = rsa.construct((t.n, t.e))
        pem = rsa_key.exportKey()

        file_name = os.path.join(base_path, 'pubkey_test_%02d.pem' % i)
        with open(file_name, 'w') as hnd:
            hnd.write(pem)
    pass
pass

