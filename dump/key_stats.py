import json
import os, sys
import keys_basic


__author__ = 'dusanklinec'


class KeyStats(object):
    CLASSIFICATION_TABLE_PATH = './classificationTable_20161018_pub.json'
    GROUPS = '''
Group I:	G&D SmartCafe 4.x, G&D SmartCafe 6.0
Group II:	GNU Crypto 2.0.1
Group III:	NXP J2D081, NXP J2E145G
Group IV:	PGPSDK 4 FIPS
Group V:	OpenSSL 1.0.2g
Group VI:	Oberthur Cosmo Dual 72k
Group VII:	NXP J2A080, NXP J2A081, NXP J3A081, NXP JCOP 41 v2.2.1
Group VIII:	Bouncy Castle 1.53, Cryptix JCE 20050328, FlexiProvider 1.7p7, mbedTLS 2.2.1, SunRsaSign (OpenJDK 1.8), SunRsaSign OpenJDK 1.8.0
Group IX:	Gemalto GXP E64
Group X:	Bouncy Castle 1.54, Crypto++ 5.6.3, Microsoft .NET, Microsoft CNG, Microsoft CryptoAPI
Group XI:	Botan 1.11.29, cryptlib 3.4.3, Feitian JavaCOS A22, Feitian JavaCOS A40, gemalto gcx4 72k, Gemalto GCX 72K, GNU Libgcrypt 1.6.5, libgcrypt 1.6.5, GNU Libgcrypt 1.6.5 FIPS, LibTomCrypt 1.17, Nettle 3.2, Oberthur Cosmo 64, OpenSSL FIPS 2.0.12, PGPSDK 4, WolfSSL 3.9.0, Utimaco Security Server Se50, OpenSSL 1.0.2g FIPS 2.0.12, libgcrypt 1.6.5 FIPS, SafeNet Luna SA-1700
Group XII:	Infineon JTOP 80K
Group XIII:	G&D SmartCafe 3.2'''

    def __init__(self):
        self.data = None
        self.sources_masks = {}
        self.sources_masks_prob = {}
        self.sources_cn = {}
        self.table_prob = {}
        self.groups_sources_map = {}
        self.sources_groups_map = {}

    def load_tables(self, fname=CLASSIFICATION_TABLE_PATH):
        # Load source grouping
        gcand = [x.strip() for x in self.GROUPS.split('\n') if len(x) > 0]
        for line in gcand:
            parts = [x.strip() for x in line.split(':', 1)]
            grp = parts[0]
            sources = [x.strip() for x in parts[1].split(',')]

            self.groups_sources_map[grp] = sources
            for source in sources:
                self.sources_groups_map[source.lower()] = grp
            pass

        # Load distributions
        with open(fname, mode='r') as fh:
            data = fh.read()
            self.data = json.loads(data)
            table = self.data['table']

            for source in table:
                self.sources_masks[source] = {}
                self.sources_masks_prob[source] = {}

                count = 0
                mask_gen = keys_basic.generate_pubkey_mask()
                for mask in mask_gen:
                    if mask not in table[source]:
                        self.sources_masks[source][mask] = 0
                    else:
                        self.sources_masks[source][mask] = table[source][mask]
                        count += table[source][mask]

                self.sources_cn[source] = count

                mask_gen = keys_basic.generate_pubkey_mask()
                for mask in mask_gen:
                    if mask not in table[source]:
                        self.sources_masks_prob[source][mask] = 0.0
                    else:
                        self.sources_masks_prob[source][mask] = float(table[source][mask]) / count

            # Merge very similar sources to one category
            # ...

            # Compute table
            mask_gen = keys_basic.generate_pubkey_mask()
            for mask in mask_gen:
                self.table_prob[mask] = {}
                for source in self.sources_masks_prob:
                    self.table_prob[mask][source] = self.sources_masks_prob[source][mask]

            # Normalize table to one
            mask_gen = keys_basic.generate_pubkey_mask()
            for mask in mask_gen:
                total = sum(self.table_prob[mask].values())
                for source in self.sources_masks_prob:
                    if total < 0.0000000001:
                        self.table_prob[mask][source] = None
                    else:
                        self.table_prob[mask][source] *= (1.0/total)
        pass

    def src_to_group(self, src):
        return self.sources_groups_map[src.lower()]

    def group_to_src(self, grp):
        return self.group_to_src(grp)[0]

    def match_keys(self, keys):

        pass





