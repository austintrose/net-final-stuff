import os
import whois
from django.db import connection
from random import random
from threading import Thread
from time import sleep
from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain, 
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain, WhoisQuery)

def do_whois(start_inc, end_ninc):
    # Get this thread's chunk of AZDs from DB.
    azds = AddedZoneDomain.objects.order_by('pk').filter(pk__gte=start_inc, pk__lte=end_ninc)
    
    for azd in azds:
        domain_name = azd.name + "." + azd.tld

        # Don't make new WHOIS if this one has been done.
        existing = WhoisQuery.objects.filter(domain_name=domain_name)
        if existing.count() > 0:
            continue

        try:
            w = whois.whois(domain_name)
        except Exception, e:
            continue

        if not w.registrar:
            print "No registrar", domain_name
            continue

        if type(w.creation_date) == type([]):
            cd = w.creation_date[0]
        else:
            cd = w.creation_date

        if w.country:
            country = w.country
        else:
            country = "?"

        new_q, created = WhoisQuery.objects.get_or_create(domain_name=domain_name, registrar=w.registrar, country=country, creation=cd)
        print domain_name, created
            
class Command(BaseCommand):
    def handle(self, *args, **options):
        threads = []
        width = 1000000
        bounds = [(1+i*width, 1+(i+1)*width) for i in range(30)]
        for start_inc, end_ninc in bounds:
            new_thread = Thread(target=do_whois, args=(start_inc, end_ninc))
            threads.append(new_thread)
            new_thread.start()

        print "joining", len(threads)
	for t in threads:
            t.join()

