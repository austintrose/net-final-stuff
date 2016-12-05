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
from domains.models import (AddedZoneDomain, RemovedZoneDomain,
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def set_dd():
    return defaultdict(set)

def list_dd():
    return defaultdict(list)

def top_malware(nameserver_domains):
    print "%s_ns_top_malware" % tld
    ns_malware_count = []
    for ns, domains_dict in nameserver_domains.iteritems():
        bad_set = domains_dict['bad']
        bad_count = len(bad_set)
        ns_malware_count.append((ns, bad_count))

    ns_malware_count = sorted(ns_malware_count, key=lambda x: -x[1])
    for ns, count in ns_malware_count:
        print ns, count

def top_overlap(nameserver_domains):
    print "%s_ns_top_overlap" % tld
    domain_set_to_ns_set = defaultdict(set)
    for ns, domains_dict in nameserver_domains.iteritems():
        domain_set_to_ns_set[tuple(domains_dict['all'])].add(ns)

    domain_set_ns_set_pairs = domain_set_to_ns_set.iteritems()
    for domain_set, ns_set in sorted(domain_set_ns_set_pairs, key=lambda x: -len(x[0])):
        print len(domain_set), tuple(ns_set)

def collect_for(tld):
    infile = open('/home/atrose/%s_ns_data' % tld, 'rb')
    nameserver_domains = pickle.load(infile)
    infile.close()

    # Matching groups for BIZ
    # group_regex = {
    #     '(A|B).NS36.DE' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('[AB].NS36.DE')
    #     },
    #     'NS(1|4).CSOF.NET' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('NS(1|4).CSOF.NET')
    #     },
    #     'DNS(1|2).NAME-SERVICES.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('DNS(1|2).NAME-SERVICES.COM')
    #     },
    #     'DNS(3|4).NAME-SERVICES.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('DNS(3|4).NAME-SERVICES.COM')
    #     },
    #     'DNS5.NAME-SERVICES.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('DNS5.NAME-SERVICES.COM')
    #     },
    #     'NS6(09|10).DOMAINCONTROL.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('NS6(3|4).DOMAINCONTROL.COM')
    #     },
    #     'DNS(1|2|3|4).REGWAY.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('DNS(1|2|3|4).REGWAY.COM')
    #     },
    #     'NS(1|2|3).SHOPCO.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('NS(1|2|3).SHOPCO.COM')
    #     },
    #     'NS(7|8).KODDOS.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('NS(7|8).KODDOS.COM')
    #     },
    #     'NS(1|2).NAMESELF.COM' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('NS(1|2).NAMESELF.COM')
    #     },
    # }

    # Matching groups for COM
    group_regex = {

        # 'NS(1|2).EFTYDNS.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2).EFTYDNS')
        # },

        # 'DNS(1|2|3|4|5).NAME-SERVICES.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('DNS(1|2|3|4|5).NAME-SERVICES')
        # },

        # 'NS(1|2).REGWAY.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2).REGWAY')
        # },

        'NS(10|09).DOMAINCONTROL.COM' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS(10|09).DOMAINCONTROL')
        },

        'NS5(3|4).DOMAINCONTROL.COM' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS5(3|4).DOMAINCONTROL')
        },

        'NS1(3|4).DOMAINCONTROL.COM' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS1(3|4).DOMAINCONTROL')
        },

        'NS6(3|4).DOMAINCONTROL.COM' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS6(3|4).DOMAINCONTROL')
        },

        'NS2(7|8).DOMAINCONTROL.COM' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS2(7|8).DOMAINCONTROL')
        },

        # 'DNS(1|2).REGISTRAR-SERVERS.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('DNS(1|2).REGISTRAR-SERVERS')
        # },

        # 'NS(1|2|3|4).OIGJAEIUG.XYZ' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2|3|4).OIGJAEIUG.XYZ')
        # },

        # 'NS(6|5).CONECTARHOSTING.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(6|5).CONECTARHOSTING')
        # },

        # 'NS(7|8).ROOKDNS.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(7|8).ROOKDNS')
        # },

        # 'NS(1|2).BLUEHOST.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2).BLUEHOST')
        # },

        # '(A|B).NS36.DE' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('(A|B).NS36.DE')
        # },

        # 'NS(1|2).LAMMYMITCH.PW' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2).LAMMYMITCH.PW')
        # },

        # 'NS(1|2).RISHON-LEZION.NET' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS(1|2).RISHON-LEZION.NET')
        # },

        # 'NS839(7|8).HOSTGATOR.COM' : {
        #     'ns': [],
        #     'domains': list_dd(),
        #     'rex': re.compile('NS839(7|8).HOSTGATOR')
        # },
    }

    # Figure out which NS match which groups.
    for ns, domains_dict in nameserver_domains.iteritems():
        ns_all_set = domains_dict['all']
        ns_bad_set = domains_dict['bad']

        for group_name, matches_dict in group_regex.iteritems():
            rex = matches_dict['rex']
            if rex.match(ns):
                matches_dict['domains']['all'].append(domains_dict['all'])
                matches_dict['domains']['bad'].append(domains_dict['bad'])
                matches_dict['ns'].append(ns)
                nameserver_domains[ns] = False
                break


    analysis = []
    for group_name, matches_dict in group_regex.iteritems():
        matching_ns_list = matches_dict['ns']
        bad_domains_sets = matches_dict['domains']['bad']
        all_domains_sets = matches_dict['domains']['all']

        union_all_domains = union_domain_sets(all_domains_sets)
        union_size = len(union_all_domains)
        intersection_all_domains = intersection_domain_sets(all_domains_sets)
        intersection_size = len(intersection_all_domains)

        if union_size == 0:
            print '0 union:', group_name
            continue

        jaccard_index = 100.0 * float(intersection_size) / union_size
        bad_count = len(union_domain_sets(bad_domains_sets))
        toxicity = 100.0 * float(bad_count) / union_size

        analysis.append({'group_name': group_name,
                         'jaccard': jaccard_index,
                         'malware_count': bad_count,
                         'toxicity': toxicity,
                         'all_unique': union_all_domains,
                         'ns_matches': matches_dict['ns']})

    for d in sorted(analysis, key=lambda x: -x['malware_count']):
        print d['group_name'], '\tbad', d['malware_count'], '\tjac', d['jaccard'], '\ttox', d['toxicity']
        # print d['ns_matches']
        print




class Command(BaseCommand):
    def handle(self, *args, **options):
        # collect_for("BIZ")
        collect_for("COM")


def intersection_domain_sets(domain_sets):
    if len(domain_sets) == 0:
        return set()

    if len(domain_sets) == 1:
        return domain_sets[0]

    start = domain_sets[0] & domain_sets[1]

    for ds in domain_sets[2:]:
        start = start & ds

    return start

def union_domain_sets(domain_sets):
    start = set()

    for ds in domain_sets:
        start = start | ds

    return start

