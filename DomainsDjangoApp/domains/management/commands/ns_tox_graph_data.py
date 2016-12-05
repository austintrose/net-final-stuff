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

def list_dd():
    return defaultdict(list)

def nameserver_domains_dd():
    return defaultdict(list_dd)


def collect_for(tld):
    infile = open('/home/atrose/%s_ns_data' % tld, 'rb')
    nameserver_domains = pickle.load(infile)
    infile.close()

    # For each name server, generate a number for its toxicity.
    ns_tox_bad_count_list = []
    for ns, domains_dict in nameserver_domains.iteritems():
        bad_set = domains_dict['bad']
        all_set = domains_dict['all']
        bad_count = len(bad_set)
        tox = (100.0 * len(bad_set)) / len(all_set)
        ns_tox_bad_count_list.append((ns, tox, bad_count))
        print ns, tox, bad_count


    ns_names_only = [x[0] for x in ns_tox_bad_count_list]

    all_tld_azd = AddedZoneDomain.objects.filter(tld=tld)
    all_tld_ns = set()

    print "Making set of possible NS"
    for azd in all_tld_azd:
        new_s = set(azd.nameservers.values_list('name', flat=True))
        all_tld_ns.update(new_s)

    print "Adding missing"
    for ns in all_tld_ns:
        if not ns in ns_names_only:
            print ns, 'not in data'
            ns_tox_bad_count_list.append((ns, 0.0, 0))


    ns_tox_bad_count_list = sorted(ns_tox_bad_count_list, key=lambda x: -x[2])
    outfile = open('/home/atrose/%s_ns_tox_datapoints' % tld, 'wb')
    pickle.dump(ns_tox_bad_count_list, outfile)
    outfile.close()

    # group_regex = {
    #     '[A,B].NS36.DE' : {
    #         'ns': [],
    #         'domains': list_dd(),
    #         'rex': re.compile('[AB].NS36.DE')
    #     },
    # }


    # for ns in ns_list:
    #     for k, d in group_regex.iteritems():
    #         rex = d['rex']
    #         if rex.match(ns):
    #             old_all = nameserver_domains[ns]['all']
    #             old_good = nameserver_domains[ns]['good']
    #             old_bad = nameserver_domains[ns]['bad']
    #             d['domains']['all'].append(old_all)
    #             d['domains']['good'].append(old_good)
    #             d['domains']['bad'].append(old_bad)
    #             d['ns'].append(ns)
    #             nameserver_domains[ns] = False
    #             break
    #     else:
    #         pass
            # print ns, "not matched"


    # ns_and_bad_count = [(ns, len(nameserver_domains[ns]['bad'])) for
    #                     ns in nameserver_domains.keys()]

    # print tld, 'top bad counts'
    # for ns, bad_count in sorted(ns_and_bad_count, key=lambda x: -x[1])[:100]:
    #     print ns.strip(), bad_count


    # short_map = {}
    # for ns in nameserver_domains.keys():
    #     all_domains_assoc = nameserver_domains[ns]['all']
    #     short_list = tuple(sorted(all_domains_assoc)[:10])
    #     short_map[ns] = short_list

    # short_list = sorted([(v,k) for (k,v) in short_map.iteritems()])
    # dlist_to_ns = defaultdict(list)
    # for list_of_domain, ns in short_list:
    #     dlist_to_ns[list_of_domain].append(ns)

    # print "%s NS associations" % tld
    # for k,v in sorted(dlist_to_ns.iteritems(), key=lambda x: -len(x[0]))[:100]:
    #     if len(v) > 1:
    #         print v, len(k)
    # outfile = open('group_regex', 'wb')
    # pickle.dump(group_regex, outfile)
    # outfile.close()
    # exit(0)

    # SHOW NOT MATCHES ONES
    # print 'DIDNT MATCH'
    # for ns in sorted(ns_list):
    #     if nameserver_domains[ns] == False:
    #         continue
    #     all_d = nameserver_domains[ns]['all']
    #     good = nameserver_domains[ns]['good']
    #     bad = nameserver_domains[ns]['bad']

    #     print ns
    #     print sorted(all_d)[:5]
    #     print

    # print
    # print
    exit(0)
    # print "DID MATCH"

    # analy = []
    # for ns_group in group_regex.keys():
    #     matching_ns = group_regex[ns_group]['ns']
    #     good_domains_lists = group_regex[ns_group]['domains']['good']
    #     bad_domains_lists = group_regex[ns_group]['domains']['bad']
    #     all_domains_lists = group_regex[ns_group]['domains']['all']

    #     intersect_count = float(intersection_domain_lists(all_domains_lists))
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

