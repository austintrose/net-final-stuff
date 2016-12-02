import os
import datetime
import re
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain, 
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def pk_to_matches(azd_pk):
    azd = AddedZoneDomain.objects.get(pk=azd_pk)
    matches = AddedMalwareDomain.objects.filter(name=azd.name, tld=azd.tld)
    return matches

def pk_has_expiry_notice(pk):
    for ns in AddedZoneDomain.objects.get(pk=pk).nameservers.all():
        if "EXPIR" in ns.name:
            return True
    return False

looking_at_tld = "COM"

class Command(BaseCommand):
    def handle(self, *args, **options):

        # Read PKs with matches from list.
        with open('/home/atrose/domain_matches.txt', 'r') as f:
            lines = f.readlines()
        pks = [ int(l[l.find('pk=')+3:].strip()) for l in lines]

        # Only look at COM.
        pks = [pk for pk in pks if AddedZoneDomain.objects.get(pk=pk).tld == looking_at_tld]

        # Filter expired NS
        pks = [pk for pk in pks if not pk_has_expiry_notice(pk)]

        # Zip pks with lists of matching malware domains.
        pks_and_matches = [(pk, pk_to_matches(pk)) for pk in pks]

        # Start keying by domain.
        domain_to_azd_dates = defaultdict(list)
        domain_to_amd = {}
        for pk, matches in pks_and_matches:
            match_dates = [amd.added for amd in matches]
            azd = AddedZoneDomain.objects.get(pk=pk)

            domain_to_azd_dates[azd.name].append(azd.added)
            domain_to_amd[azd.name] = match_dates

        my_grand_list = []
        for domain in domain_to_azd_dates.keys():
            my_grand_list.append({'domain': domain, 'zone_dates': domain_to_azd_dates[domain], 'malware_dates': domain_to_amd[domain]})

        # Only use cases where there's one malware addition date. 
        # Processing two sets of dates is hard.
        reduced = [i for i in my_grand_list if len(i['malware_dates']) == 1]

        # Convert dates to distances between.
        numbers = [dates_to_number(i['zone_dates'], i['malware_dates'][0]) for i in my_grand_list]
        numbers = [n for n in numbers if n != 9999]

        print looking_at_tld
        print numbers

def dates_to_number(azd_dates, malware_date):
    lowest_positive_delta = 9999
    for d in azd_dates:
        delta = malware_date - d
        if delta.days < lowest_positive_delta and delta.days >= 0:
            lowest_positive_delta = delta.days
    return lowest_positive_delta
