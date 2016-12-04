# Collect the nameservers of domains we know ended up in malware blacklist.
# Then, for only those nameservers come up with the list of all domains which
# were associated.


import os
import re
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

    # Look at the nameservers of known malware domains.
    nameserver_domains = defaultdict(lambda: defaultdict(list))
    for pk in pks:
        azd = AddedZoneDomain.objects.get(pk=pk)

        # Only look at one TLD.
        if azd.tld != tld:
            continue

        # Take every nameserver associated with this bad domain.
        for ns in azd.nameservers.all():
            if 'RENEW' in ns.name:
                continue
            if 'SUSPENDED' in ns.name:
                continue
            nameserver_domains[ns.name]['all'].extend(ns.added_domains.values_list('name', flat=True))
            nameserver_domains[ns.name]['bad'].append(azd.name)

    for ns, d in nameserver_domains.iteritems():
        unique_all = list(set(d['all']))
        unique_bad = list(set(d['bad']))
        good_from_all = [a for a in unique_all if not a in unique_bad]

        nameserver_domains[ns]['all'] = unique_all
        nameserver_domains[ns]['good'] = good_from_all
        nameserver_domains[ns]['bad'] = unique_bad

    ns_list = nameserver_domains.keys()

    group_regex = {
        '[A,B].NS36.DE' : {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('[AB].NS36.DE')
        },

        'NS[0-9]*.CSOF.NET': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.CSOF.NET')
        },

        'DNS[0-9]*.NAME-SERVICES.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('DNS[0-9]*.NAME-SERVICES.COM')
        },

        'DNS[0-9]*.REGWAY.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('DNS[0-9]*.REGWAY.COM')
        },

        '[0-9A-Z]*.BITCOIN-DNS.HOSTING': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('[0-9A-Z]*.BITCOIN-DNS.HOSTING')
        },

        'NS[0-9]*.IPAGE.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.IPAGE.COM')
        },

        'NS[0-9]*.SHOPCO.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.SHOPCO.COM')
        },

        'NS[0-9]*.NAMESELF.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.NAMESELF.COM')
        },

        'STVL113289.[A-Z]*.OBOX-DNS.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('STVL113289.[A-Z]*.OBOX-DNS.COM')
        },

        'DNS[0-9]*.FASTDNS24.[A-Z]*': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('DNS[0-9]*.FASTDNS24.[A-Z]*')
        },

        'FREE[0-9]*.GOOGIEHOST.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('FREE[0-9]*.GOOGIEHOST.COM')
        },

        'FREE[0-9]*.HOSTGUY.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('FREE[0-9]*.HOSTGUY.COM')
        },

        'NS[0-9]*.LINEVAST.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.LINEVAST.COM')
        },

        'DNS[12345].REGISTRAR-SERVERS.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('DNS[12345].REGISTRAR-SERVERS.COM')
        },

        'NS[12].KODDOS.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[12].KODDOS.COM')
        },

        'NS[78].KODDOS.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[78].KODDOS.COM')
        },

        'NS[34].KODDOS.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[34].KODDOS.COM')
        },

        'N[1234].SINKHOLE.CH': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('N[1234].SINKHOLE.CH')
        },

        'NS[1234].SINKHOLE.CH': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[1234].SINKHOLE.CH')
        },

        'NS[0-9]*.NAZWA.PL': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS[0-9]*.NAZWA.PL')
        },

        'NS6[78].DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS6[78].DOMAINCONTROL.COM')
        },

        'NS(09|10).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(09|10).DOMAINCONTROL.COM')
        },

        'NS(19|20).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(19|20).DOMAINCONTROL.COM')
        },

        'NS(27|28).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(27|28).DOMAINCONTROL.COM')
        },

        'NS(49|50).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(49|50).DOMAINCONTROL.COM')
        },

        'NS(53|54).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(53|54).DOMAINCONTROL.COM')
        },

        'NS(63|64).DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS(63|64).DOMAINCONTROL.COM')
        },

        'NS0[78].DOMAINCONTROL.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS0[78].DOMAINCONTROL.COM')
        },

        'NS807[78].HOSTGATOR.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS807[78].HOSTGATOR.COM')
        },

        'NS808[12].HOSTGATOR.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS808[12].HOSTGATOR.COM')
        },

        'NS839[78].HOSTGATOR.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS839[78].HOSTGATOR.COM')
        },

        'NS402[12].HOSTGATOR.COM': {
            'ns': [],
            'domains': defaultdict(list),
            'rex': re.compile('NS402[12].HOSTGATOR.COM')
        },
    }

    for ns in ns_list:
        for k, d in group_regex.iteritems():
            rex = d['rex']
            if rex.match(ns):
                old_all = nameserver_domains[ns]['all']
                old_good = nameserver_domains[ns]['good']
                old_bad = nameserver_domains[ns]['bad']
                d['domains']['all'].append(old_all)
                d['domains']['good'].append(old_good)
                d['domains']['bad'].append(old_bad)
                d['ns'].append(ns)
                nameserver_domains[ns] = False
                break
        else:
            pass
            # print ns, "not matched"

    # exit(0)

    # SHOW NOT MATCHES ONES
    # print 'DIDNT MATCH'
    # for ns in sorted(ns_list):
    #     if nameserver_domains[ns] == False:
    #         continue
    #     all_d = nameserver_domains[ns]['all']
    #     good = nameserver_domains[ns]['good']
    #     bad = nameserver_domains[ns]['bad']

    #     tox = 100.0 * float(len(bad)) / (len(good) + len(bad))
    #     print ns
    #     print all_d
    #     print

    print
    print
    print "DID MATCH"

    analy = []
    for ns_group in group_regex.keys():
        matching_ns = group_regex[ns_group]['ns']
        good_domains_lists = group_regex[ns_group]['domains']['good']
        bad_domains_lists = group_regex[ns_group]['domains']['bad']
        all_domains_lists = group_regex[ns_group]['domains']['all']

        intersect_count = float(intersection_domain_lists(all_domains_lists))
        if intersect_count < 1:
            print ns_group
            for i in range(len(matching_ns)):
                print '\t',matching_ns[i], sorted(all_domains_lists[i])
            print
            continue
        union_count = union_domain_lists(all_domains_lists)
        jac = intersect_count / union_count
        bad_count = union_domain_lists(bad_domains_lists)
        tox = float(bad_count) / union_count

        analy.append({'name': ns_group,
            'jac': jac,
            'bad': bad_count,
            'tox': tox})

    # for d in sorted(analy, key=lambda x: -x['bad']):
        # print d['name'], 'bad', d['bad'], 'jac', d['jac'], 'tox', d['tox']



class Command(BaseCommand):
    def handle(self, *args, **options):
        collect_for("BIZ")
        # collect_for("COM")


def intersection_domain_lists(domain_lists):
    if len(domain_lists) == 0:
        return 0
    if len(domain_lists) == 1:
        return len(domain_lists[0])

    first, second = set(domain_lists[0]), set(domain_lists[1])
    start = first & second

    for dl in domain_lists[2:]:
        start = start & set(dl)

    return len(start)

def union_domain_lists(domain_lists):
    start = set()

    for dl in domain_lists:
        start = start | set(dl)

    return len(start)

