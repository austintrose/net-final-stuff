# TODO: Figure out how many COM domains added in each day,
# look at the distribution, see if you can model it, and see if
# domains registered on outlier days are more likely to be malware

import os
import datetime
import re
import pickle
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from threading import Thread
from domains.models import (AddedZoneDomain, RemovedZoneDomain, Nameserver, AddedMalwareDomain, RemovedMalwareDomain, WhoisQuery)

current_tld = "BIZ"
registrar_domains_map = defaultdict(list)
grand_return = []

class Command(BaseCommand):
    def handle(self, *args, **options):

        threads = []
        width = 100000
        bounds = [(1+i*width, 1+(i+1)*width) for i in range(21)]
        for start, end in bounds:
            new_thread = Thread(target=collect_for_bound_tld, args=(current_tld, start, end))
            threads.append(new_thread)
            new_thread.start()

        print "Joining collection"
        for t in threads:
            t.join()
        print "Joined collection"
        print len(registrar_domains_map.keys())

        threads = []
        width = len(registrar_domains_map.keys()) / 10
        bounds = [(i*width, (i+1)*width) for i in range(11)]
        for start, end in bounds:
            new_thread = Thread(target=process_list_sub, args=(start, end))
            threads.append(new_thread)
            new_thread.start()

        print "Joining processing"
        for t in threads:
            t.join()
        print "Joined processing"

        out_file = open(current_tld +  '_scatter_data', 'wb')
        pickle.dump(grand_return, out_file)
        out_file.close()
        print "Done", current_tld

def collect_for_bound_tld(tld, start, end):
    whois_queries = WhoisQuery.objects.order_by('pk').filter(pk__gte=start, pk__lt=end, domain_name__contains="." + tld)
    for who_q in whois_queries:
        domain_name = who_q.domain_name
        if domain_name[-4:] != "." + current_tld:
            print "BAD", domain_name[-4:]
            continue
        domain_no_tld = domain_name[:-4]
        registrar_domains_map[who_q.registrar].append((domain_no_tld, who_q.creation))

def process_list_sub(start, end):
    keys = sorted(registrar_domains_map.keys())[start:end]

    for i, registrar in enumerate(keys):
        print "%d / %d" % (i, end - start)
        list_of_domain_and_date = registrar_domains_map[registrar]
        filtered_list = map(lambda x: domain_was_in_malware(x[0], x[1], current_tld), list_of_domain_and_date)
        normal_counts = len([a for a in filtered_list if not a])
        malware_counts = len([a for a in filtered_list if a])
        grand_return.append({'registrar_name': registrar, 'good': normal_counts, 'bad': malware_counts})

def domain_was_in_malware(domain, creation, tld):
    mws = AddedMalwareDomain.objects.filter(tld=tld, name__icontains=domain, added__gte=creation)
    rem = RemovedMalwareDomain.objects.filter(tld=tld, name__icontains=domain, removed__gte=creation)
    if mws.count() > 0 or rem.count() > 0:
        return True
    return False
