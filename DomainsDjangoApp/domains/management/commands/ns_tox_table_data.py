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

    # Matching groups for NS.
    group_regex = {
        '(A|B).NS36.DE' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('[AB].NS36.DE')
        },
        'NS(1|4).CSOF.NET' : {
            'ns': [],
            'domains': list_dd(),
            'rex': re.compile('NS(1|4).CSOF.NET')
        },
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

    # print 'Not grouped:'
    # for ns in sorted(nameserver_domains.keys()):
    #     if nameserver_domains[ns] == False:
    #         continue
    #     else:
    #         print ns, 'not grouped'

    # exit(0)

    analy = []
    for group_name, matches_dict in group_regex.iteritems():
        matching_ns_list = matches_dict['ns']
        bad_domains_sets = matches_dict['domains']['bad']
        all_domains_sets = matches_dict['domains']['all']

        union_size = union_domain_sets_size(all_domains_sets)
        intersection_size = intersection_domain_sets_size(all_domains_sets)
        jaccard_index = float(intersection_size) / union_size

        print matching_ns_list, jaccard_index
    return
    #     union_count = union_domain_lists(all_domains_lists)

    #     if intersect_count < 1 or union_count < 1:
    #         # print ns_group
    #         # for i in range(len(matching_ns)):
    #         #     print '\t',matching_ns[i], sorted(all_domains_lists[i])
    #         # print
    #         continue

    #     jac = intersect_count / union_count
    #     bad_count = union_domain_lists(bad_domains_lists)
    #     tox = float(bad_count) / union_count

    #     analy.append({'name': ns_group,
    #         'jac': jac,
    #         'bad': bad_count,
    #         'tox': tox})

    # for d in sorted(analy, key=lambda x: -x['bad']):
    #     print d['name'], 'bad', d['bad'], 'jac', d['jac'], 'tox', d['tox']



class Command(BaseCommand):
    def handle(self, *args, **options):
        collect_for("BIZ")
        # collect_for("COM")


def intersection_domain_sets_size(domain_sets):
    if len(domain_sets) == 0:
        return 0

    if len(domain_sets) == 1:
        return len(domain_sets[0])

    start = domain_sets[0] & domain_sets[1]

    for ds in domain_sets[2:]:
        start = start & set(dl)

    return len(start)

def union_domain_sets_size(domain_sets):
    start = set()

    for ds in domain_sets:
        start = start | ds

    return len(start)

