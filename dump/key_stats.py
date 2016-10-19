import json
import os, sys
import keys_basic


__author__ = 'dusanklinec'


class KeyStats(object):
    CLASSIFICATION_TABLE_PATH = './classificationTable_20161018_pub.json'

    def __init__(self):
        self.data = None
        self.sources_masks = {}
        self.sources_masks_prob = {}
        self.sources_cn = {}
        self.table_prob = {}

    def load_tables(self, fname=CLASSIFICATION_TABLE_PATH):
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





