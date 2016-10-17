from ebclient.process_data import ProcessData
from ebclient.create_uo import TemplateFields, KeyTypes, Environment, Gen
from ebclient.eb_create_uo import *
from ebclient.uo import Configuration, Endpoint, SimpleRetry, UO
from ebclient.crypto_util import *
import OpenSSL
import Crypto
from Crypto.PublicKey.RSA import RSAImplementation
import os


__author__ = 'dusanklinec'


cfg = Configuration()
cfg.endpoint_process = Endpoint.url('http://site2.enigmabridge.com:11180')
cfg.endpoint_enroll = Endpoint.url('http://site2.enigmabridge.com:11182')
cfg.api_key = 'API_TEST'
cfg.retry = SimpleRetry(max_retry=1, jitter_base=1000, jitter_rand=250)


def create_rsa(cfg):
    cou = CreateUO(configuration=cfg,
                   tpl={
                       TemplateFields.environment: Environment.DEV
                   })

    rsa_key = cou.create_rsa(2048)
    return rsa_key


rsa = RSAImplementation()
base_path = '/tmp'

for idx in range(84, 100):
    print "Generating key %02d" % idx
    key = create_rsa(cfg)
    rsa_key = rsa.construct((key.n, key.e))
    pem = rsa_key.exportKey()

    file_name = os.path.join(base_path, 'pubkey_%02d.pem' % idx)
    with open(file_name, 'w') as hnd:
        hnd.write(pem)
    pass


if __name__ == "__main__":
    print "ok"

