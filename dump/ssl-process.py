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
import utils

import Tkinter
sys.modules['tkinter'] = Tkinter

import scipy
from scipy.stats import chisquare
import matplotlib
import matplotlib.pyplot as plt
from numpy.random import rand
import random
import numpy as np
import math


def random_subset(a, size):
    tmp = range(0, len(a))
    res = set([])
    while len(res) < size:
        e = random.choice(tmp)
        res.add(e)

    res_elem = []
    for i in res:
        res_elem.append(a[i])
    return list(res_elem)


def print_res(res, st, error=None):
    total = 0.0
    res = sorted(res, key=lambda x: x[1], reverse=True)
    for tup in res:
        total += tup[1]
    for idx,tup in enumerate(res):
        if tup[1] < 1e-200:
            continue
        if error is None:
            print(' - %s [%2.4f %%] %s [%s]' % (tup[1], tup[1]*(100.0/total), tup[0], st.src_to_group(tup[0])))
        else:
            print(' - %s [%2.4f %%] std: %f %s [%s]' % (tup[1], tup[1]*(100.0/total), error[idx], tup[0], st.src_to_group(tup[0])))


def key_val_to_list(src_dict):
    res = []
    for src in src_dict:
        val = src_dict[src]
        res.append((src, val))
    res = sorted(res, key=lambda x: x[1], reverse=True)
    return res


def val_if_none(val, default):
    return val if val is not None else default


def comp_total_match(masks, st):
    src_total_match = {}
    for src in st.table_prob:
        src_total_match[src] = 1

        for idx, mask in enumerate(masks):
            val = val_if_none(st.table_prob[src][mask], 0)
            src_total_match[src] *= val

    # Total output
    return key_val_to_list(src_total_match)


def total_match(certs, st):
    print_res(comp_total_match(certs, st), st)


def plot_key_mask_dist(masks_db, st):
    mask_map, mask_max, mask_map_x, mask_map_y, mask_map_last_x, mask_map_last_y = keys_basic.generate_pubkey_mask_indices()
    scale = float(mask_max/2.0)
    for mask in masks_db:
        mask_idx = mask_map[mask]
        parts = [x.replace('|', '') for x in mask.split('|', 1)]

        # y = 0
        # x = mask_idx

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


def bar_chart(sources=None, values=None, res=None, error=None, xlabel=None, title=None):
    if res is not None:
        sources = [x[0] for x in res]
        values = [x[1] for x in res]

    plt.rcdefaults()
    y_pos = np.arange(len(sources))
    plt.barh(y_pos, values, align='center', xerr=error, alpha=0.4)
    plt.yticks(y_pos, sources)
    plt.xlabel(xlabel)
    plt.title(title)
    plt.show()


def main():
    parser = argparse.ArgumentParser(description='Key processing tool')
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

    parser.add_argument('--pubs', dest='pubs', nargs=argparse.ZERO_OR_MORE,
                        help='File with public keys (PEM)')

    parser.add_argument('--certs', dest='certs', nargs=argparse.ZERO_OR_MORE,
                        help='File with certificates (PEM)')

    parser.add_argument('--ossl', dest='ossl', type=int, default=None, help='OpenSSL generator')

    parser.add_argument('--subs', dest='subs', action='store_const', const=True,
                        help='Plot random subgroups charts')
    parser.add_argument('--subs-k', dest='subs_k', type=int, default=5,
                        help='Size of the subset')
    parser.add_argument('--subs-n', dest='subs_n', type=int, default=1000,
                        help='Number of subsets to sample')

    parser.add_argument('--key-dist', dest='plot_key_dist', action='store_const', const=True,
                        help='Plots key mask distribution')

    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='file with ssl-dump json output')

    args = parser.parse_args()

    masks_db = []
    cert_db = []
    keys_db = []

    # Input = ssl-dump output
    if len(args.files) > 0:
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
            masks_db.append(cert['pubkey']['mask'])

        if args.verbose:
            print('Certificate database size %d' % len(cert_db))

        if args.dump_json:
            print(json.dumps(cert_db))

        if args.dump_cert:
            for cert in cert_db:
                print cert['cert']

    # public key list processing
    if args.pubs is not None:
        for pubf in args.pubs:
            with open(pubf, mode='r') as fh:
                data = fh.read()
                keys = []
                for match in re.finditer(r'-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----', data, re.MULTILINE | re.DOTALL):
                    key = match.group(0)
                    keys.append(key)

                # pubkey -> mask
                for key in keys:
                    pub = serialization.load_pem_public_key(key, utils.get_backend())
                    mask = keys_basic.compute_key_mask(pub.public_numbers().n)
                    keys_db.append(pub)
                    masks_db.append(mask)

    if args.certs is not None:
        for certf in args.certs:
            with open(certf, mode='r') as fh:
                data = fh.read()
                certs = []
                for match in re.finditer(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', data, re.MULTILINE | re.DOTALL):
                    cert = match.group(0)
                    certs.append(cert)

                # cert -> mask
                for cert in certs:
                    x509 = utils.load_x509(str(cert))
                    pub = x509.public_key()
                    mask = keys_basic.compute_key_mask(pub.public_numbers().n)
                    keys_db.append(pub)
                    masks_db.append(mask)

    if args.ossl is not None:
        for i in range(0, args.ossl):
            print('Generating RSA1024 key %03d' % i)
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)
            key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

            priv = serialization.load_pem_private_key(key_pem, None, utils.get_backend())
            mask = keys_basic.compute_key_mask(priv.public_key().public_numbers().n)
            keys_db.append(priv.public_key())
            masks_db.append(mask)

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

    # masks processing part
    if len(masks_db) == 0:
        return

    # Simple match
    print('Per-key matching: ')
    for idx,mask in enumerate(masks_db):
        print('Key %02d, mask: %s' % (idx, mask))

        res = []
        for src in st.table_prob:
            val = st.table_prob[src][mask]
            res.append((src, val if val is not None else 0))
        print_res(res, st)

    # Total key matching
    print('Fit for all keys in one distribution:')
    res = comp_total_match(masks_db, st)
    print_res(res, st)
    res = st.res_src_to_group(res)
    # bar_chart(res=res, title='Fit for all keys')

    # Sum it
    print('All keys sums:')
    src_total_match = {}
    for src in st.table_prob:
        src_total_match[src] = 0
        for idx, mask in enumerate(masks_db):
            src_total_match[src] += val_if_none(st.table_prob[src][mask], 0)

    # Total output
    res = key_val_to_list(src_total_match)
    print_res(res, st)
    res = st.res_src_to_group(res)
    # bar_chart(res=res, title='Sum for all keys')

    # Avg + mean
    print('Avg + mean:')
    src_total_match = {}
    for src in st.table_prob:
        src_total_match[src] = []
        for idx, mask in enumerate(masks_db):
            val = val_if_none(st.table_prob[src][mask], 0)
            src_total_match[src].append(val)
    res=[]
    devs=[]
    for src in st.sources:
        m = np.mean(src_total_match[src])
        s = np.std(src_total_match[src])
        res.append((src, m))
        devs.append(s)

    # Total output
    print_res(res, st, error=devs)
    # bar_chart(res=res, error=devs, title='Avg for all keys + error')

    # Random subset
    if args.subs:
        masks_db_tup = []
        for idx,mask in enumerate(masks_db):
            masks_db_tup.append((idx,mask))

        # Many random subsets, top groups
        subs_size = args.subs_k
        subs_count = args.subs_n
        groups_cnt = {}
        for i in range(0, subs_count):
            masks = random_subset(masks_db_tup, subs_size)
            ids = [x[0] for x in masks]
            ids.sort()

            res = comp_total_match([x[1] for x in masks], st)

            total = 0.0
            for tup in res:
                total += tup[1]
            for tup in res:
                src = tup[0]
                score = long(math.floor(tup[1]*(1000.0/total)))
                if score == 0:
                    continue

                grp = st.src_to_group(src)
                if grp not in groups_cnt:
                    groups_cnt[grp] = score
                else:
                    groups_cnt[grp] += score

                if src not in groups_cnt:
                    groups_cnt[src] = score
                else:
                    groups_cnt[src] += score

            # best group only
            # best_src = res[0][0]
            # best_grp = st.src_to_group(best_src)
            # if best_grp not in groups_cnt:
            #     groups_cnt[best_grp] = 1
            # else:
            #     groups_cnt[best_grp] += 1

        sources = st.groups
        values = []
        for source in sources:
            val = groups_cnt[source] if source in groups_cnt else 0
            values.append(val)
        bar_chart(sources, values,
                  xlabel='# of occurrences as top group (best fit)',
                  title='Groups vs. %d random %d-subsets' % (subs_count, subs_size))


    # Chisquare
    for source in st.sources_masks:
        cn = st.sources_cn[source]
        # chi = chisquare()
        # gen = keys_basic.generate_pubkey_mask()


    # 2D Key plot
    if args.plot_key_dist:
        plot_key_mask_dist(masks_db, st)





# Launcher
if __name__ == "__main__":
    main()