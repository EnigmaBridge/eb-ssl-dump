import json
import os, sys
import keys_basic


__author__ = 'dusanklinec'


class KeyStats(object):
    CLASSIFICATION_TABLE_PATH = './classificationTable_20161018_pub.json'
    GROUPS = '''
Group I:	G&D SmartCafe 3.2
Group II:	GNU Crypto 2.0.1
Group III:	Gemalto GXP E64
Group IV:	Infineon JTOP 80K
Group V:	Oberthur Cosmo Dual 72k
Group VI:	OpenSSL 1.0.2g
Group VII:	PGPSDK 4 FIPS
Group VIII:	G&D SmartCafe 4.x, G&D SmartCafe 6.0
Group IX:	NXP J2D081, NXP J2E145G
Group X:	NXP J2A080, NXP J2A081, NXP J3A081, NXP JCOP 41 v2.2.1
Group XI:	Bouncy Castle 1.54, Crypto++ 5.6.3, Microsoft .NET, Microsoft CNG, Microsoft CryptoAPI
Group XII:	Bouncy Castle 1.53, Cryptix JCE 20050328, FlexiProvider 1.7p7, mbedTLS 2.2.1, SunRsaSign (OpenJDK 1.8), sunrsasign openjdk 1.8.0, Utimaco Security Server Se50 LAN Appliance, utimaco security server se50
Group XIII:	Botan 1.11.29, cryptlib 3.4.3, Feitian JavaCOS A22, Feitian JavaCOS A40, Gemalto GCX 72K, gemalto gcx4 72k, libgcrypt 1.6.5, GNU Libgcrypt 1.6.5, libgcrypt 1.6.5 fips, GNU Libgcrypt 1.6.5 FIPS, LibTomCrypt 1.17, Nettle 3.2, Oberthur Cosmo 64, OpenSSL FIPS 2.0.12, openssl 1.0.2g fips 2.0.12, PGPSDK 4, SafeNet Luna SA-1700 LAN, safenet luna sa-1700, WolfSSL 3.9.0
'''

    def __init__(self):
        self.data = None
        self.sources_masks = {}
        self.sources_masks_prob = {}
        self.sources_cn = {}
        self.table_prob = {}
        self.groups = []
        self.groups_idx = {}
        self.groups_sizes = {}
        self.sources = []
        self.sources_idx = {}
        self.groups_sources_map = {}
        self.sources_groups_map = {}

    def load_tables(self, fname=CLASSIFICATION_TABLE_PATH):
        # Load source grouping
        gcand = [x.strip() for x in self.GROUPS.split('\n') if len(x) > 0]
        for line in gcand:
            parts = [x.strip() for x in line.split(':', 1)]
            grp = parts[0]
            self.groups_idx[grp.lower()] = len(self.groups)
            self.groups.append(grp)

            sources = [x.strip() for x in parts[1].split(',')]
            self.groups_sources_map[grp] = sources
            for source in sources:
                self.sources_groups_map[source.lower()] = grp
            self.groups_sizes[grp.lower()] = len(sources)

        # Load distributions
        with open(fname, mode='r') as fh:
            data = fh.read()
            self.data = json.loads(data)
            table = self.data['table']

            for source in table:
                self.sources_masks[source] = {}
                self.sources_masks_prob[source] = {}
                self.sources_idx[source] = len(self.sources)
                self.sources.append(source)

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
            for source in self.sources_masks_prob:
                self.table_prob[source] = {}
                for mask in keys_basic.generate_pubkey_mask():
                    self.table_prob[source][mask] = self.sources_masks_prob[source][mask]

            # Normalize table to one - on the line
            mask_gen = keys_basic.generate_pubkey_mask()
            for mask in mask_gen:
                total = 0.0
                for source in self.sources_masks_prob:
                    total += self.sources_masks_prob[source][mask]
                for source in self.sources_masks_prob:
                    if total < 1e-250:
                        self.table_prob[source][mask] = None
                    else:
                        self.table_prob[source][mask] *= (1.0/total)
        pass

    def src_to_group(self, src):
        return self.sources_groups_map[src.lower()]

    def group_to_src(self, grp):
        return self.group_to_src(grp)[0]

    def get_group_idx(self, group):
        return self.groups_idx[group.lower()]

    def get_source_idx(self, src):
        return self.sources_idx[src]

    def get_group_size(self, group):
        return self.groups_sizes[group.lower()]

    def data_src_to_group(self, src_data, merger=lambda x,y: x+y, equalize=True):
        """
        Projects a dictionary src -> data to groups -> data
        :param src_data:
        :return:
        """
        res = {}
        for src in src_data:
            grp = self.src_to_group(src)
            val = src_data[src]

            if grp not in res:
                res[grp] = val
                continue

            res[grp] = merger(res[grp], val)

        if equalize:
            for grp in res:
                res[grp] /= self.get_group_size(grp)

        return res

    def res_src_to_group(self, res, merger=lambda x,y: x+y, equalize=True):
        """
        Projects an array res [src, data] to [group, data]
        Warning, size of groups is not the same, some equalization needs to be done
        :param res:
        :param merger:
        :return:
        """
        out_res = []
        for grp in self.groups:
            out_res.append((grp, None))
        for src, data in res:
            grp = self.src_to_group(src)
            idx = self.get_group_idx(grp)
            if out_res[idx][1] is None:
                out_res[idx] = (grp, data)
                continue
            out_res[idx] = (grp, merger(out_res[idx][1], data))

        if equalize:
            for grp in self.groups:
                idx = self.get_group_idx(grp)
                out_res[idx] = (grp, out_res[idx][1] / self.get_group_size(grp))
        
        return out_res

    def match_keys(self, keys):

        pass





