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

import Tkinter
sys.modules['tkinter'] = Tkinter

import scipy
from scipy.stats import chisquare
import matplotlib
import matplotlib.pyplot as plt
from numpy.random import rand


def print_res(res, st):
    total = 0.0
    res = sorted(res, key=lambda x: x[1], reverse=True)
    for tup in res:
        total += tup[1]
    for tup in res:
        if tup[1] < 1e-200:
            continue
        print(' - %s [%2.4f %%] %s [%s]' % (tup[1], tup[1]*(100.0/total), tup[0], st.src_to_group(tup[0])))


def main():
    parser = argparse.ArgumentParser(description='SSL dump')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=None,
                        help='Number of threads to use for cert download')
    parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                        help='enables debug mode')
    parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                        help='enables verbose mode')
    parser.add_argument('--dump-json', dest='dump_json', action='store_const', const=True,
                        help='dumps JSON of the filtered certificates')
    parser.add_argument('--dump-cert', dest='dump_cert', action='store_const', const=True,
                        help='dumps PEM of the filtered certificates')
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
            if args.verbose:
                print('Organization filtered out %s' % org)
            continue
        cert_db.append(cert)

    if args.verbose:
        print('Certificate database size %d' % len(cert_db))

    if args.dump_json:
        print(json.dumps(cert_db))

    if args.dump_cert:
        for cert in cert_db:
            print cert['cert']

    # Load statistics
    st = key_stats.KeyStats()
    st.load_tables()
    if args.verbose:
        print('Source stats: ')
        for src in st.sources_cn:
            print(' %30s: %08d' % (src, st.sources_cn[src]))

    # mask indices
    mask_map, mask_max, mask_map_x, mask_map_y, mask_map_last_x, mask_map_last_y = keys_basic.generate_pubkey_mask_indices()
    print('Max mask 1D config: [%d]' % mask_max)
    print('Max mask 2D config: [%d, %d]' % (mask_map_last_x, mask_map_last_y))

    # Simple match
    print('Per-key matching: ')
    for idx,cert in enumerate(cert_db):
        mask = cert['pubkey']['mask']
        print('Key %02d, mask: %s' % (idx, mask))

        res = []
        for src in st.table_prob[mask]:
            val = st.table_prob[mask][src]
            res.append((src, val if val is not None else 0))
        print_res(res, st)

    # Total key matching
    print('Fit for all keys in one distribution:')
    src_total_match = {}
    for idx,cert in enumerate(cert_db):
        mask = cert['pubkey']['mask']

        for src in st.table_prob[mask]:
            val = st.table_prob[mask][src]
            if val is None:
                val = 0

            if src not in src_total_match:
                src_total_match[src] = 1

            src_total_match[src] *= val

    # Total output
    res = []
    for src in src_total_match:
        val = src_total_match[src]
        res.append((src, val))
    print_res(res, st)







    # # Likelihood computation
    # print('Likelihood matching: ')
    # src_likelihood = {}
    # for idx,cert in enumerate(cert_db):
    #     mask = cert['pubkey']['mask']
    #
    #
    # for idx,cert in enumerate(cert_db):
    #     mask = cert['pubkey']['mask']
    #     print('Key %02d, mask: %s' % (idx, mask))
    #
    #     res = []
    #     for src in st.table_prob[mask]:
    #         res.append((src, st.table_prob[mask][src]))
    #
    #     res = sorted(res, key=lambda x: x[1], reverse=True)
    #     for tup in res:
    #         print(' - %04f %s [%s]' % (tup[1], tup[0], st.src_to_group(tup[0])))

    # Chisquare
    for source in st.sources_masks:
        cn = st.sources_cn[source]
        # chi = chisquare()
        # gen = keys_basic.generate_pubkey_mask()


    return

    # 2D Key plot
    scale = float(mask_max/2.0)
    for cert in cert_db:
        mask = cert['pubkey']['mask']
        mask_idx = mask_map[mask]
        parts = [x.replace('|', '') for x in mask.split('|', 1)]

        y = 0
        x = mask_idx

        # y = (mask_idx >> 5) & 0x1f
        # x = mask_idx & 0x1f

        x = mask_map_x[parts[0]]
        y = mask_map_y[parts[1]]
        plt.scatter(x, y,
                    s=scale,
                    alpha=0.3)
        pass

    plt.scatter(mask_map_last_x, mask_map_last_y, c='red', s=scale, alpha=0.3)
    plt.legend()
    plt.grid(True)
    plt.show()






# Launcher
if __name__ == "__main__":
    main()