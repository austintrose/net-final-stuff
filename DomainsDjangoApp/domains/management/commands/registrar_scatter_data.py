# TODO: Figure out how many COM domains added in each day,
# look at the distribution, see if you can model it, and see if
# domains registered on outlier days are more likely to be malware

import os
import datetime
import re
import pickle
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain, Nameserver, AddedMalwareDomain, RemovedMalwareDomain, WhoisQuery)

class Command(BaseCommand):
    def handle(self, *args, **options):
        biz_data = collect_for("BIZ")
        biz_file = open('biz_scatter_data', 'wb')
        pickle.dump(biz_data, biz_file)
        biz_file.close()
        print "Done BIZ"

        com_data = collect_for("COM")
        com_file = open('com_scatter_data', 'wb')
        pickle.dump(com_data, com_file)
        com_file.close()
        print "Done COM"

def collect_for(tld):
    grand_return = []

    whois_queries = WhoisQuery.objects.filter(domain_name__contains=tld)

    # Create a mapping between registrars and list of domains associated.
    registrar_domains_map = defaultdict(list)
    for who_q in whois_queries:
        # Remove .TLD from end of domain name, because that's not how they're
        # stored in AddedMalwareDomain.
        domain_name = who_q.domain_name
        domain_name = domain_name[:-4]

        # Update mapping.
        registrar_domains_map[who_q.registrar].append(domain_name)

    for k,v in registrar_domains_map.iteritems():
        filtered_list = map(lambda x: domain_was_in_malware(x, tld), v)
        registrar_domains_map[k] = filtered_list

        normal_counts = len([a for a in filtered_list if not a])
        malware_counts = len([a for a in filtered_list if a])

        grand_return.append({'registrar_name': k, 'good': normal_counts, 'bad': malware_counts})

    return grand_return


def domain_was_in_malware(domain, tld):
    mws = AddedMalwareDomain.objects.filter(tld=tld, name__icontains=domain)
    if mws.count() > 0:
        return True
    return False
