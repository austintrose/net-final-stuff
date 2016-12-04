# Collect the nameservers of domains we know ended up in malware blacklist.
# Then, for only those nameservers come up with the list of all domains which
# were associated.


import os
import datetime
import re
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain,
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def collect_for(tld):
    # Read PKs with matches from list.
    with open('/home/atrose/domain_matches.txt', 'r') as f:
        lines = f.readlines()
    pks = [ int(l[l.find('pk=')+3:].strip()) for l in lines]

    # Look at
    nameserver_domains = defaultdict(lambda: defaultdict(list))
    for pk in pks:
        azd = AddedZoneDomain.objects.get(pk=pk)

        # Only look at one TLD.
        if azd.tld != tld:
            continue

        # Take every nameserver associated with this bad domain.
        for ns in azd.nameservers.all():
            nameserver_domains[ns.name]['all'].extend(ns.added_domains.values_list('name', flat=True))
            nameserver_domains[ns.name]['bad'].append(azd.name)

    for ns, d in nameserver_domains.iteritems():
        unique_all = list(set(d['all']))
        unique_bad = list(set(d['bad']))
        filter_all = [a for a in unique_all if not a in unique_bad]

        nameserver_domains[ns]['all'] = filter_all
        nameserver_domains[ns]['bad'] = unique_bad

    ns_list = nameserver_domains.keys()

    ns_bad_tox = []
    for ns in sorted(ns_list):
        good = nameserver_domains[ns]['all']
        bad = nameserver_domains[ns]['bad']

        tox = 100.0 * float(len(bad)) / (len(good) + len(bad))
        ns_bad_tox.append((ns, len(bad), tox))

    # Sort by number of bad domains
    for ns, bad, tox in sorted(ns_bad_tox, key=lambda x: x[1]):
        print ns, '\t', bad, '\t', tox

class Command(BaseCommand):
    def handle(self, *args, **options):
        collect_for("BIZ")
        # collect_for("COM")

