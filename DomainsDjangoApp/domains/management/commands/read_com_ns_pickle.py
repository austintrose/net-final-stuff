# Collect the nameservers of domains we know ended up in malware blacklist.
# Then, for only those nameservers come up with the list of all domains which
# were associated.


import pickle
import os
import re
import datetime
import re
from collections import defaultdict
from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain, Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def list_dd():
    return defaultdict(list)

def nameserver_domains_dd():
    return defaultdict(list_dd)

class Command(BaseCommand):
    def handle(self, *args, **options):
        infile = open('/home/atrose/com_nameserver_domains_for_tox', 'rb')

        nameserver_domains = pickle.load(infile)

        group_regex = {
            'NOTHING' : {
                'ns': [],
                'domains': list_dd(),
                'rex': re.compile('NOTHING')
            },
        }

        ns_and_bad_count = [(ns, len(nameserver_domains[ns]['bad'])) for
                            ns in nameserver_domains.keys()]

        for ns, bad_count in sorted(ns_and_bad_count, key=lambda x: -x[1])[:100]:
            print ns.strip(), bad_count

        return
        short_map = {}
        for ns in nameserver_domains.keys():
            all_domains_assoc = nameserver_domains[ns]['all']
            short_list = tuple(sorted(all_domains_assoc)[:10])
            short_map[ns] = short_list

        short_list = sorted([(v,k) for (k,v) in short_map.iteritems()])
        dlist_to_ns = defaultdict(list)
        for list_of_domain, ns in short_list:
            dlist_to_ns[list_of_domain].append(ns)

        print "COM NS associations"
        for k,v in sorted(dlist_to_ns.iteritems(), key=lambda x: -len(x[0])):
            if len(v) > 1:
                print v, len(k)

