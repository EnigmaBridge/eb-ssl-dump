import requests
import math
import re
import traceback
import argparse
import sys
import os
import json
from collections import OrderedDict


__author__ = 'dusanklinec'


class ToolsLoader(object):
    BASE_URL = 'http://www.gwebtools.com/ns-spy/'

    def __init__(self, ns=None, attempts=5):
        self.attempts = attempts
        self.ns = ns
        self.total = None
        self.per_page = None

    def load(self, idx=None):
        for i in range(0, self.attempts):
            try:
                return self.load_once(idx)
            except Exception as e:
                traceback.print_exc()
                pass
        return None

    def load_once(self, idx=None):
        url = self.BASE_URL + self.ns

        if idx is not None:
            url += '/%d' % idx

        res = requests.get(url, timeout=20)
        if math.floor(res.status_code / 100) != 2.0:
            res.raise_for_status()

        data = res.text

        # parse total
        if self.total is None:
            match = re.search(r'Total of domains on ([^:]+?):\s*([\d]+)', data)
            if match is not None:
                self.total = int(match.group(2))
                print self.total

        # parse domains
        regex = re.compile(r"<li class='col-xs-4' style='list-style:none; word-wrap: break-word;'>\s*"
                           r"<a href='(.+?)'>([^<]+?)</a></li>", re.IGNORECASE)

        domains = set([])
        for match in regex.finditer(data):
            if match is None:
                continue
            tmp = match.group(2)
            try:
                domains.add(tmp.strip().lower())
            except:
                traceback.print_exc()
                pass

        if self.per_page is None:
            self.per_page = len(domains)

        return domains


def load_last_page(dump, ns):
    if dump is None or not os.path.exists(dump):
        return None
    with open(dump, 'r') as fhtmp:
        tmp_json = json.loads(fhtmp.read())
        if ns not in tmp_json:
            return None
        if 'pages' not in tmp_json[ns]:
            return None
        tmp_pages = tmp_json[ns]['pages']
        if tmp_pages is None or len(tmp_pages) == 0:
            return None
        return max(tmp_pages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NS dump')
    parser.add_argument('-p', dest='page', default=None)
    parser.add_argument('-w', dest='dump', default=None)
    parser.add_argument('ns', nargs=argparse.ONE_OR_MORE, default=[], help='ns')
    args = parser.parse_args()

    if len(args.ns) == 0:
        parser.print_usage()
        sys.exit(1)

    for ns in args.ns:
        print('NS dump %s' % ns)

        t = ToolsLoader(ns=ns)
        page = args.page
        if page is None:
            page = load_last_page(args.dump, ns)
            print('Starting from page %d' % (page if page is not None else 0))

        domains = set([])
        while True:
            part_domains = t.load(page)
            if part_domains is None:
                print('Warning! Empty domain list on page ' + page)
                sys.exit(1)

            part_domains_list = list(part_domains)
            if page is None:
                page = 0

            # When doing parallelization, do this on the main thread
            if args.dump is not None:
                ex_json = OrderedDict()
                if os.path.exists(args.dump):
                    with open(args.dump, 'r') as fh:
                        ex_json = json.loads(fh.read())
                if ns not in ex_json:
                    ex_json[ns] = OrderedDict()
                    ex_json[ns]['page'] = 0
                    ex_json[ns]['pages'] = []
                    ex_json[ns]['domains'] = []

                # last page
                ex_json[ns]['page'] = page

                # pages list
                pages = set(ex_json[ns]['pages'])
                pages.add(page)
                pages = list(pages)
                pages.sort()
                ex_json[ns]['pages'] = pages

                ex_domains = set(ex_json[ns]['domains'])
                for d in part_domains_list:
                    ex_domains.add(d)

                ex_domains = list(ex_domains)
                ex_domains.sort()
                ex_json[ns]['domains'] = ex_domains

                with open(args.dump, 'w') as fh:
                    fh.write(json.dumps(ex_json))

            print('Page %s loaded' % page)
            print(part_domains_list)

            for d in part_domains_list:
                domains.add(d)

            page = page + 1 if page is not None else 1
            if t.total is not None \
                    and t.per_page is not None \
                    and page is not None \
                    and t.per_page * page >= t.total:
                break
        pass

        domains_list = list(domains)
        domains_list.sort()
        for x in domains_list:
            print x






