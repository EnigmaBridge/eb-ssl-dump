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
from sklearn.decomposition import IncrementalPCA, PCA, SparsePCA, KernelPCA
from matplotlib.backends.backend_pdf import PdfPages
import mixture
import logging, coloredlogs


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def random_subset_idx(a, count):
    tmp = range(0, len(a))
    res = set([])
    while len(res) < count:
        e = random.choice(tmp)
        res.add(e)

    res_elem = []
    for i in res:
        res_elem.append(a[i])
    return list(res_elem), res


def random_subset(a, count):
    return random_subset_idx(a, count)[0]


def print_res(res, st, error=None, loglikelihood=False):
    total = 0.0
    res = sorted(res, key=lambda x: x[1], reverse=True)
    if loglikelihood:
        print('Loglikelihood results: ')
    for tup in res:
        if tup[1] is not None:
            total += tup[1]
    for idx, tup in enumerate(res):
        val = tup[1]
        prop = 'N/A'
        if val is None:
            continue
        if not loglikelihood:
            prop = '%2.4f %%' % (val*(100.0/total))
        if error is None:
            print(' - %s [%s] %s [%s]' % (val, prop, tup[0], st.src_to_group(tup[0])))
        else:
            print(' - %s [%s] std: %s %s [%s]' % (val, prop, error[idx], tup[0], st.src_to_group(tup[0])))


def key_val_to_list(src_dict):
    res = []
    for src in src_dict:
        val = src_dict[src]
        res.append((src, val))
    res = sorted(res, key=lambda x: x[1], reverse=True)
    return res


def val_if_none(val, default):
    return val if val is not None else default


def comp_total_match_dict(masks, st, loglikelihood=False):
    src_total_match = {}
    for src in st.table_prob:
        src_total_match[src] = 1.0 if not loglikelihood else 0.0

        for idx, mask in enumerate(masks):
            val = val_if_none(st.table_prob[src][mask], 0)
            if loglikelihood:
                if val == 0.0 or src_total_match[src] is None:
                    src_total_match[src] = None
                else:
                    src_total_match[src] += math.log(val)
            else:
                src_total_match[src] *= val
    return src_total_match


def comp_total_match(masks, st, loglikelihood=False):
    src_total_match = comp_total_match_dict(masks, st, loglikelihood=loglikelihood)
    return key_val_to_list(src_total_match)


def total_match(certs, st, loglikelihood=False):
    print_res(comp_total_match(certs, st, loglikelihood=loglikelihood), st)


def plot_key_mask_dist(masks_db, st):
    mask_map, mask_max, mask_map_x, mask_map_y, mask_map_last_x, mask_map_last_y = keys_basic.generate_pubkey_mask_indices()
    scale = float(mask_max/2.0)
    for mask in masks_db:
        parts = [x.replace('|', '') for x in mask.split('|', 1)]

        # y = (mask_idx >> 5) & 0x1f
        # x = mask_idx & 0x1f

        x = mask_map_x[parts[0]]
        y = mask_map_y[parts[1]]
        plt.scatter(x, y, marker='s',
                    s=scale,
                    alpha=0.3)
        pass

    # Distribution of pk
    max_x = mask_map_last_x
    cdf = [0] * max_x
    df = [0] * max_x
    for mask in masks_db:
        proj_mask = keys_basic.project_mask(mask, [0,1,2,3,4,5])
        proj_idx = mask_map_x[proj_mask]
        df[proj_idx] += 1
    for i in range(0, max_x):
        cdf[i] = (cdf[i-1] if i > 0 else 0) + df[i]

    cdf_scale = float(mask_map_last_y)/cdf[max_x-1]
    cdf = [x*cdf_scale for x in cdf]
    plt.plot(range(0, mask_map_last_x), cdf, 'bo', range(0, mask_map_last_x), cdf, 'k')

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


def get_group_desc(grp, st):
    desc = []
    sources = st.groups_sources_map[grp]
    max_rng = min(4, len(sources))
    for idx in range(max_rng):
        src = sources[idx]
        if len(src) <= 12:
            desc.append(src)
            continue
        desc.append(src[0:8] + '..' + src[-4:])
    return ', '.join(desc)


# Main - argument parsing + processing
def main():
    logger.debug('App started')

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
    parser.add_argument('--filter-domain', dest='filter_domain',
                        help='Filter out certificates issued for the given domain - regex')

    parser.add_argument('--pubs', dest='pubs', nargs=argparse.ZERO_OR_MORE,
                        help='File with public keys (PEM)')

    parser.add_argument('--certs', dest='certs', nargs=argparse.ZERO_OR_MORE,
                        help='File with certificates (PEM)')

    parser.add_argument('--ossl', dest='ossl', type=int, default=None, help='OpenSSL generator')

    parser.add_argument('--per-key-stat', dest='per_key_stat', action='store_const', const=True,
                        help='Print prob matching for each key')

    parser.add_argument('--subs', dest='subs', action='store_const', const=True,
                        help='Plot random subgroups charts')
    parser.add_argument('--subs-k', dest='subs_k', type=int, default=5,
                        help='Size of the subset')
    parser.add_argument('--subs-n', dest='subs_n', type=int, default=1000,
                        help='Number of subsets to sample')

    parser.add_argument('--pca-src', dest='pca_src', action='store_const', const=True,
                        help='Plot PCA sampled distribution vs collected one')
    parser.add_argument('--pca-src-n', dest='pca_src_n', type=int, default=10000,
                        help='Number of subsets to sample from source distributions')
    parser.add_argument('--pca-src-k', dest='pca_src_k', type=int, default=3,
                        help='Size of the subset from the source distribution')

    parser.add_argument('--pca-grp', dest='pca_grp', action='store_const', const=True,
                        help='Plot PCA on the input keys (groups)')

    parser.add_argument('--mixture', dest='mixture', action='store_const', const=True,
                        help='Mixture distribution on masks - sources')

    parser.add_argument('--distrib', dest='distrib', action='store_const', const=True,
                        help='Plot distributions - to the PDF')

    parser.add_argument('--distrib-mix', dest='distribmix', action='store_const', const=True,
                        help='Plot distributions groups mixed with sources')

    parser.add_argument('--key-dist', dest='plot_key_dist', action='store_const', const=True,
                        help='Plots key mask distribution')

    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='file with ssl-dump json output')

    args = parser.parse_args()

    last_src_id = 0
    src_names = []
    masks_db = []
    masks_src = []
    cert_db = []
    keys_db = []

    # Input = ssl-dump output
    if len(args.files) > 0:
        # Cert Organization Filtering
        re_org = None if args.filter_org is None else re.compile(args.filter_org, re.IGNORECASE)
        # Domain filtering
        re_dom = None if args.filter_domain is None else re.compile(args.filter_domain, re.IGNORECASE)

        # Process files
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
                for cert in json_data:
                    org = cert['org']
                    if org is None:
                        org = ''
                    if re_org is not None and re_org.match(org) is None:
                        if args.verbose:
                            print('Organization filtered out %s' % org)
                        continue
                    if re_dom is not None:
                        dom_match = re_dom.match(cert['cn']) is not None
                        for alt in cert['alts']:
                            dom_match |= re_dom.match(alt) is not None
                        if not dom_match:
                            if args.verbose:
                                print('Domain filtered out %s' % cert['cn'])
                            continue

                    cert_db.append(cert)
                    masks_db.append(cert['pubkey']['mask'])
                    masks_src.append(last_src_id)
            src_names.append(fl)
            last_src_id += 1

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
                print('File %s keys num: %d' % (pubf, len(keys)))

                # pubkey -> mask
                for key in keys:
                    pub = serialization.load_pem_public_key(key, utils.get_backend())
                    mask = keys_basic.compute_key_mask(pub.public_numbers().n)
                    keys_db.append(pub)
                    masks_db.append(mask)
                    masks_src.append(last_src_id)
            src_names.append(pubf)
            last_src_id += 1

    # extract public key from certificate
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
                    masks_src.append(last_src_id)
            src_names.append(certf)
            last_src_id += 1

    # generate openssl keys on the fly
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
            masks_src.append(last_src_id)
        src_names.append('ossl-%d' % args.ossl)
        last_src_id+=1

    # Load statistics
    st = key_stats.KeyStats()
    st.load_tables()
    if args.verbose:
        print('Source stats: ')
        for src in st.sources_cn:
            print(' %30s: %08d' % (src, st.sources_cn[src]))
        print('Group stats:')
        for grp in st.groups:
            print(' %30s: %02d' % (grp, st.get_group_size(grp)))

    # mask indices
    mask_map, mask_max, mask_map_x, mask_map_y, mask_map_last_x, mask_map_last_y = keys_basic.generate_pubkey_mask_indices()
    print('Max mask 1D config: [%d]' % mask_max)
    print('Max mask 2D config: [%d, %d]' % (mask_map_last_x, mask_map_last_y))

    # masks processing part
    if len(masks_db) == 0:
        return

    # Simple match
    if args.per_key_stat:
        print('Per-key matching: ')
        for idx, mask in enumerate(masks_db):
            print('Key %02d, mask: %s' % (idx, mask))

            res = []
            for src in st.table_prob:
                val = st.table_prob[src][mask]
                res.append((src, val if val is not None else 0))
            print_res(res, st)

    # Total key matching
    use_loglikelihood = True
    print('Fit for all keys in one distribution:')
    total_weights = src_total_match = comp_total_match_dict(masks_db, st, loglikelihood=use_loglikelihood)
    res = key_val_to_list(src_total_match)
    print_res(res, st, loglikelihood=use_loglikelihood)
    res = st.res_src_to_group(res)
    # bar_chart(res=res, title='Fit for all keys')

    # Avg + mean
    print('Avg + mean:')
    src_total_match = {}  # source -> [p1, p2, p3, p4, ..., p_keynum]
    for src in st.table_prob:
        src_total_match[src] = []
        for idx, mask in enumerate(masks_db):
            val = keys_basic.aggregate_mask(st.sources_masks_prob[src], mask)
            if use_loglikelihood:
                if total_weights[src] is not None:
                    src_total_match[src].append(val + total_weights[src])
                else:
                    src_total_match[src].append(-9999.9)
            else:
                src_total_match[src].append(val * total_weights[src])
            pass
        pass
    res=[]
    devs=[]
    for src in st.sources:
        m = np.mean(src_total_match[src])
        s = np.std(src_total_match[src])
        res.append((src, m))
        devs.append(s)

    # Total output
    print_res(res, st, error=devs, loglikelihood=use_loglikelihood)
    # bar_chart(res=res, error=devs, title='Avg for all keys + error')

    # PCA on the keys - groups
    keys_grp_vec = []
    for idx, mask in enumerate(masks_db):
        keys_grp_vec.append([])
        for src in st.groups:
            keys_grp_vec[idx].append(0)
        for idxs,src in enumerate(st.sources):
            grp = st.src_to_group(src)
            prob = st.table_prob[src][mask]
            keys_grp_vec[idx][st.get_group_idx(grp)] += prob

    if args.pca_grp:
        X = np.array(keys_grp_vec)
        pca = PCA(n_components=2)
        pca.fit(X)
        X_transformed = pca.transform(X)
        print('PCA mean: %s, components: ' % pca.mean_)
        print(pca.components_)

        masks_src_np = np.array(masks_src)
        plt.rcdefaults()
        colors = matplotlib.cm.rainbow(np.linspace(0, 1, last_src_id))
        for src_id in range(0, last_src_id):
            plt.scatter(X_transformed[masks_src_np == src_id, 0],
                        X_transformed[masks_src_np == src_id, 1],
                        label=src_names[src_id], color=colors[src_id], alpha=0.25, marker=',')
        plt.legend(loc="best", shadow=False, scatterpoints=1)
        plt.show()

    # Random subset
    if args.subs:
        masks_db_tup = []
        for idx,mask in enumerate(masks_db):
            masks_db_tup.append((idx, mask, masks_src[idx]))

        # Many random subsets, top groups
        subs_size = args.subs_k
        subs_count = args.subs_n
        groups_cnt = {}
        subs_data = []
        subs_data_mark = []
        dsrc_num = last_src_id+1

        # Take subs_count samples fro the input masks_db, evaluate it, prepare for PCA
        for i in range(0, subs_count):
            masks = random_subset(masks_db_tup, subs_size)
            src_total_match = comp_total_match_dict([x[1] for x in masks], st)
            res = key_val_to_list(src_total_match)

            total = 0.0
            for tup in res:
                total += tup[1]

            # data vectors for PCA
            tmp_data = []
            for idx, tmp_src in enumerate(st.sources):
                val = src_total_match[tmp_src]
                val = long(math.floor(val*(1000.0/total)))
                tmp_data.append(val)

            # PCA on groups.
            # if want PCA on sources, use subs_data.append(tmp_data)
            subs_data.append(tmp_data)
            # res_grp_val = st.res_src_to_group(zip(st.sources, tmp_data))
            # subs_data.append([x[1] for x in res_grp_val])

            subs_dsources = {}
            max_dsrc = (0,0)
            for dsrc in [x[2] for x in masks]:
                if dsrc not in subs_dsources:
                    subs_dsources[dsrc] = 0
                subs_dsources[dsrc] += 1

            for dsrc in subs_dsources:
                if subs_dsources[dsrc] > max_dsrc[1]:
                    max_dsrc = (dsrc, subs_dsources[dsrc])
            tmp_mark = max_dsrc[0]

            if max_dsrc[1] == subs_size:
                tmp_mark = max_dsrc[0]
            else:
                tmp_mark = last_src_id

            subs_data_mark.append(tmp_mark)

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

            # Equalize group sizes
            for grp in st.groups:
                grp = grp.lower()
                if grp in groups_cnt:
                    groups_cnt[grp] /= float(st.get_group_size(grp))

            # best group only
            # best_src = res[0][0]
            # best_grp = st.src_to_group(best_src)
            # if best_grp not in groups_cnt:
            #     groups_cnt[best_grp] = 1
            # else:
            #     groups_cnt[best_grp] += 1

        print('Combinations: (N, k)=(%d, %d) = %d' % (subs_count, subs_size, scipy.misc.comb(subs_count, subs_size)))

        sources = st.groups
        values = []
        for source in sources:
            val = groups_cnt[source] if source in groups_cnt else 0
            values.append(val)
        bar_chart(sources, values,
                  xlabel='# of occurrences as top group (best fit)',
                  title='Groups vs. %d random %d-subsets' % (subs_count, subs_size))

        # PCA stuff
        X = np.array(subs_data)
        pca = PCA(n_components=2)
        pU, pS, pV = pca._fit(X)
        X_transformed = pca.transform(X)
        subs_data_mark_pca = np.array(subs_data_mark)

        print('Sources: ')
        print(st.sources)

        print('PCA input data shape %d x %d' % (len(subs_data), len(subs_data[0])))
        print('PCA mean: \n%s \nPCA components: \n' % pca.mean_)
        print(pca.components_)

        print('PCA components x: ')
        for x in pca.components_[0]:
            print x
        print('\nPCA components y: ')
        for y in pca.components_[1]:
            print y

        # print('\nPCA U,S,V')
        # print(pU)
        # print(pS)
        # print(pV)

        colors = ['blue', 'red', 'green', 'gray', 'yellow']

        plt.rcdefaults()
        for src_id in range(0, dsrc_num):
            plt.scatter(X_transformed[subs_data_mark_pca == src_id, 0],
                        X_transformed[subs_data_mark_pca == src_id, 1],
                        color=colors[src_id], alpha=0.5 if src_id < dsrc_num-1 else 0.2)
        plt.legend(loc="best", shadow=False, scatterpoints=1)

        # plt.scatter([x[0] for x in X_transformed],
        #             [x[1] for x in X_transformed],
        #             alpha=0.5)

        plt.show()

        # PCA against defined sources with known distributions?
        # Creates "background distribution" we want to match to
        if args.pca_src:
            # Four axes, returned as a 2-d array
            plt.rcdefaults()
            #f, axarr = plt.subplots(len(st.sources), 1)
            src_k = args.pca_src_k
            src_n = args.pca_src_n

            # prepare PDF
            ppdf = PdfPages('test.pdf') # todo-filenae-from-set
            sources_to_test = st.sources[20:25] + [x for x in st.sources if 'micro' in x.lower()]

            # compute for each source
            src_mark_idx = len(subs_data_mark)
            subs_data_src = subs_data
            subs_data_mark_src = subs_data_mark
            for src_idx, source in enumerate(sources_to_test):
                # cur_plot = axarr[src_idx]
                cur_plot = plt

                print('Plotting PCA source %s %d/%d' % (source, src_idx+1, len(sources_to_test)))

                # Extend subs_data_src with draws from the source distribution
                for i in range(0, src_n):
                    masks = []
                    for tmpk in range(0, src_k):
                        masks.append(st.sample_source_distrib(source))
                    src_total_match = comp_total_match_dict(masks, st)
                    res = key_val_to_list(src_total_match)

                    total = 0.0
                    for tup in res:
                        total += tup[1]

                    # data vectors for PCA
                    tmp_data = []
                    for idx, tmp_src in enumerate(st.sources):
                        val = src_total_match[tmp_src]
                        val = long(math.floor(val*(1000.0/total)))
                        tmp_data.append(val)

                    # PCA on groups.
                    # if want PCA on sources, use subs_data.append(tmp_data)
                    subs_data_src.append(tmp_data)
                    subs_data_mark_src.append(src_mark_idx)

                # PCA stuff
                X = np.array(subs_data_src)
                pca = PCA(n_components=2)
                pU, pS, pV = pca._fit(X)
                X_transformed = pca.transform(X)
                subs_data_mark_pca = np.array(subs_data_mark_src)

                colors = ['blue', 'red', 'green', 'gray', 'yellow']

                # plot input sources
                for src_id in range(0, dsrc_num):
                    cur_plot.scatter(X_transformed[subs_data_mark_pca == src_id, 0],
                                     X_transformed[subs_data_mark_pca == src_id, 1],
                                     color=colors[src_id], alpha=0.5 if src_id < dsrc_num-1 else 0.2)

                # plot the source stuff
                cur_plot.scatter(X_transformed[subs_data_mark_pca == src_mark_idx, 0],
                                 X_transformed[subs_data_mark_pca == src_mark_idx, 1],
                                 color='gray', marker='+', alpha=0.05)

                cur_plot.legend(loc="best", shadow=False, scatterpoints=1)
                cur_plot.title('Src [%s] input: %s' % (source, (', '.join(src_names))))

                cur_plot.savefig(ppdf, format='pdf')
                cur_plot.clf()

            print('Finalizing PDF...')
            # plt.savefig(ppdf, format='pdf')
            ppdf.close()
            pass

    if args.distrib:
        # Plotting distributions for groups, to the PDF
        plt.rcdefaults()
        ppdf = PdfPages('groups_distrib.pdf')

        # Compute for each source
        range_ = st.masks
        range_idx = np.arange(len(st.masks))
        for grp_idx, grp in enumerate(st.groups):
            cur_data = st.groups_masks_prob[grp]
            raw_data = [cur_data[x] for x in st.masks]
            cur_plot = plt

            logger.debug('Plotting distribution %02d/%02d : %s ' % (grp_idx+1, len(st.groups), grp))
            axes = cur_plot.gca()
            axes.set_xlim([0, len(st.masks)])
            cur_plot.bar(range_idx, raw_data, linewidth=0, width=0.4)
            cur_plot.title('%s (%s)' % (grp, get_group_desc(grp, st)))
            cur_plot.savefig(ppdf, format='pdf')
            cur_plot.clf()

        # Print input data - per source
        max_src = max(masks_src)
        bars = []
        for src_id in range(max_src+1):
            axes = plt.gca()
            axes.set_xlim([0, len(st.masks)])

            map_data = {}
            for mask in st.masks:
                map_data[mask] = 0.0
            for mask_idx, mask in enumerate(masks_db):
                if masks_src[mask_idx] == src_id:
                    map_data[mask] += 1

            raw_data = []
            for mask in st.masks:
                raw_data.append(map_data[mask])

            b1 = plt.bar(range_idx, raw_data, linewidth=0, width=0.4)
            bars.append(b1)

            plt.title('Source %d' % src_id)
            plt.savefig(ppdf, format='pdf')
            plt.clf()

        # Group distribution + source:
        if args.distribmix:
            width = 0.25
            range_idx = np.arange(len(st.masks))

            # One source to the graph
            max_src = max(masks_src)
            cur_plot = plt
            for src_id in range(max_src+1):

                bars = []
                logger.debug('Plotting mix distribution src %d ' % src_id)

                map_data = {}
                for mask in st.masks:
                    map_data[mask] = 0.0
                for mask_idx, mask in enumerate(masks_db):
                    if masks_src[mask_idx] == src_id:
                        map_data[mask] += 1

                raw_data = []
                for mask in st.masks:
                    raw_data.append(map_data[mask])
                raw_data = np.array(raw_data)
                raw_data /= float(sum(raw_data))

                for grp_idx, grp in enumerate(st.groups):
                    logger.debug(' - Plotting mix distribution %02d/%02d : %s ' % (grp_idx+1, len(st.groups), grp))

                    # Source
                    fig, ax = plt.subplots()
                    b1 = ax.bar(range_idx + width, raw_data, linewidth=0, width=width, color='r')
                    bars.append(b1)

                    # Group
                    cur_data2 = st.groups_masks_prob[grp]
                    raw_data2 = [cur_data2[x] for x in st.masks]

                    bar1 = ax.bar(range_idx, raw_data2, linewidth=0, width=width, color='b')
                    bars.append(bar1)

                    ax.legend(tuple([x[0] for x in bars]), tuple(['Src %d' % src_id, grp]))
                    ax.set_xlim([0, len(st.masks)])

                    cur_plot.title('%s + source %d' % (grp, src_id))
                    cur_plot.savefig(ppdf, format='pdf')
                    cur_plot.clf()

        logger.info('Finishing PDF')
        ppdf.close()
        pass

    if args.mixture:
        # http://www.pymix.org/pymix/index.php?n=PyMix.Tutorial#bayesmix
        # 1. Create mixture model = add discrete distributions to the package
        dists = []
        alphabet = mixture.Alphabet(st.masks)
        taken_src = []

        for src in st.sources:
            if 'openssl 1.0.2g' == src or 'microsoft .net' == src:
                pass
            else:
                continue
            print(' - Source: %s' % src)

            taken_src.append(src)
            probs = []
            for m in st.masks:
                probs.append(st.sources_masks_prob[src][m])

            d = mixture.DiscreteDistribution(len(alphabet), probs, alphabet=alphabet)
            dists.append(d)

        # 2. Create the model, for now, with even distribution among components.
        comp_weights = [1.0/len(dists)] * len(dists)
        mmodel = mixture.MixtureModel(len(dists), comp_weights, dists)
        print '-'*80
        print mmodel
        print '-'*80

        # dump mixtures to the file
        mixture.writeMixture(mmodel, 'src.mix')

        # 3. Input data - array of input masks
        masks_data = [[x] for x in masks_db]
        data = mixture.DataSet()
        data.fromList(masks_data)
        data.internalInit(mmodel)

        print masks_data
        print data
        print '---------'

        # 4. Compute EM
        # if there is a distribution in the input data which has zero matching inputs,
        # an exception will be thrown. Later - discard such source from the input...
        print mmodel.modelInitialization(data, 1)
        print('EM start: ')

        ress = []
        for r in range(10):
            mmodel.modelInitialization(data, 1)
            emres = mmodel.EM(data, 1000, 0.00000000000000001)
            ress.append(emres)
        emres = max(ress, key=lambda x: x[1])

        # print mmodel.randMaxEM(data, 10, 40, 0.1)
        print emres

        # Plot
        plt.rcdefaults()
        # plt.plot(range(0, len(emres[0][3])), [2.71828**x for x in emres[0][3]], 'o')
        # plt.plot(range(0, len(emres[0][3])), emres[0][3], 'k')
        # plt.show()

        for i in range(0,5):
            print('-------')
            for idx, src in enumerate(emres[0]):
                print('- i:%02d src: %02d, val: %s' % (i, idx, src[i]))

        colors = matplotlib.cm.rainbow(np.linspace(0, 1, len(taken_src)))
        range_ = range(0, len(emres[0][0]))
        bars = []
        for idx, src in enumerate(emres[0]):
            b1 = plt.bar(range_, [2.71828**x for x in src], color=colors[idx])
            bars.append(b1)

        plt.legend(tuple(bars), tuple(taken_src))
        plt.grid(True)
        plt.show()

        # for src in emres[0]:
        #     plt.plot(range(0, len(src)), [2.71828**x for x in src], 'o')
        #     # plt.grid(True)
        #     # plt.show()
        #
        # # plt.scatter(mask_map_last_x, mask_map_last_y, c='red', s=scale, alpha=0.3)
        # # plt.legend()
        # plt.grid(True)
        # plt.show()





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