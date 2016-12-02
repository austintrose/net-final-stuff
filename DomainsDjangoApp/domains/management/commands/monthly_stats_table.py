# import datetime

# from django.core.management.base import BaseCommand, CommandError
# from domains.models import (AddedZoneDomain, RemovedZoneDomain,
#                             Nameserver, AddedMalwareDomain, RemovedMalwareDomain, WhoisQuery)


# class Command(BaseCommand):
#     def handle(self, *args, **options):



import os
import datetime
import re
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain,
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def month_name(num):
    date = datetime.date(2016, num, 1)
    return date.strftime('%B')

def pk_to_matches(azd_pk):
    azd = AddedZoneDomain.objects.get(pk=azd_pk)
    matches = AddedMalwareDomain.objects.filter(name=azd.name, tld=azd.tld)
    return matches

def pk_has_expiry_notice(pk):
    for ns in AddedZoneDomain.objects.get(pk=pk).nameservers.all():
        if "EXPIR" in ns.name:
            return True
    return False

def azd_has_expiry_notice(azd):
    for ns in azd.nameservers.all():
        if "EXPIR" in ns.name:
            return True
    return False

looking_at_tld = "COM"

class Command(BaseCommand):
    def handle(self, *args, **options):
        for month in range(1, 13):
            print month_name(month)

            azds = AddedZoneDomain.objects.filter(added__month=month)
            print '.'
            com_azds = azds.filter(tld="COM")
            print '.'
            biz_azds = azds.filter(tld="BIZ")
            print '.'

            com_azds_noex = [a.name for a in com_azds if not azd_has_expiry_notice(a)]
            print '.'
            com_azds_noex_set = set(com_azds_noex)
            print '.'
            biz_azds_noex = [a.name for a in biz_azds if not azd_has_expiry_notice(a)]
            print '.'
            biz_azds_noex_set = set(biz_azds_noex)
            print '.'

            print "COM domains added to zone (ignoring expiry additions, and dups): %d" % len(com_azds_noex)
            print "BIZ domains added to zone (ignoring expiry additions, and dups): %d" % len(biz_azds_noex)
            print

        exit(0)


        # Read PKs with matches from list.
        with open('/home/atrose/domain_matches.txt', 'r') as f:
            lines = f.readlines()
        pks = [ int(l[l.find('pk=')+3:].strip()) for l in lines]

        # Only look at one TLD.
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

        valid_data_points = [valid_ordering(i['zone_dates'], i['malware_dates'][0]) for i in my_grand_list]
        valid_data_points = [p for p in valid_data_points if p]

        print looking_at_tld
        print len(valid_data_points)
        print valid_data_points
        exit(0)


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

def valid_ordering(azd_dates, malware_date):
    lowest_positive_delta = 9999
    for d in azd_dates:
        delta = malware_date - d
        if delta.days < lowest_positive_delta and delta.days >= 0:
            return malware_date.month
    return False

