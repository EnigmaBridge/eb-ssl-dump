import json
import os, sys

__author__ = 'dusanklinec'


class KeyStats(object):
    CLASSIFICATION_TABLE_PATH = './classificationTable_20161018_pub.json'

    def __init__(self):
        self.data = None
        self.sources_masks = {}
        self.sources_cn = {}

    def load_tables(self, fname=CLASSIFICATION_TABLE_PATH):
        with open(fname, mode='r') as fh:
            data = fh.read()
            self.data = json.loads(data)
            table = self.data['table']

            for source in table:
                self.sources_masks[source] = {}

                count = 0
                for mask in table[source]:
                    self.sources_masks[source][mask] = table[source][mask]
                    count += table[source][mask]

                self.sources_cn[source] = count
        pass





