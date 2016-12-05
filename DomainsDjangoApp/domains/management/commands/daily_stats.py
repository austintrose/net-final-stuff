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
import pickle

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain,
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

def month_name(num):
    date = datetime.date(2016, num, 1)
    return date.strftime('%B')

def pk_to_matches(azd_pk):
    azd = AddedZoneDomain.objects.get(pk=azd_pk)
    matches = AddedMalwareDomain.objects.filter(name=azd.name, tld=azd.tld, added__gte=azd.added)
    return matches

def pk_has_expiry_notice(pk):
    for ns in AddedZoneDomain.objects.get(pk=pk).nameservers.all():
        if "EXPIR" in ns.name:
            return True
        elif "RENEW" in ns.name:
            return True
        elif "SUSPENDED" in ns.name:
            return True
    return False

looking_at_tld = "COM"

class Command(BaseCommand):
    def handle(self, *args, **options):
        # Read PKs with matches from list.
        with open('/home/atrose/domain_matches.txt', 'r') as f:
            lines = f.readlines()
        pks = [ int(l[l.find('pk=')+3:].strip()) for l in lines]

        all_azds = AddedZoneDomain.objects.filter(tld=looking_at_tld)

        date_counts = defaultdict(int)
        for azd in all_azds:
            if azd.pk in pks:
                pks.remove(azd.pk)
                continue

            elif pk_has_expiry_notice(azd.pk):
                continue

            date_counts[azd.added] += 1


        outfile = open(tld + '_date_counts', 'wb')
        pickle.dump(date_counts, outfile)
        outfile.close()
        print "added to %s dates, normal or malware. THERE SHOULD BE ZEROES" % looking_at_tld
        for k in sorted(date_counts.keys()):
            print k, date_counts[k]


        # # Only look at one TLD.
        # pks = [pk for pk in pks if AddedZoneDomain.objects.get(pk=pk).tld == looking_at_tld]

        # # Filter expired NS
        # pks = [pk for pk in pks if not pk_has_expiry_notice(pk)]

        # # Zip pks with lists of matching malware domains.
        # pks_and_matches = [(pk, pk_to_matches(pk)) for pk in pks]

        # # Start keying by domain.
        # domain_to_azd_dates = defaultdict(list)
        # domain_to_amd = {}
        # for pk, matches in pks_and_matches:
        #     match_dates = [amd.added for amd in matches]
        #     azd = AddedZoneDomain.objects.get(pk=pk)

        #     domain_to_azd_dates[azd.name].append(azd.added)
        #     domain_to_amd[azd.name] = match_dates

        # my_grand_list = []
        # for domain in domain_to_azd_dates.keys():
        #     my_grand_list.append({'domain': domain, 'zone_dates': domain_to_azd_dates[domain], 'malware_dates': domain_to_amd[domain]})

        # # Only use cases where there's one malware addition date.
        # # Processing two sets of dates is hard.
        # reduced = [i for i in my_grand_list if len(i['malware_dates']) == 1]

        # valid_data_points = [valid_ordering(i['zone_dates'], i['malware_dates'][0]) for i in my_grand_list if len(i['malware_dates']) > 0]
        # valid_data_points = [p for p in valid_data_points if p]

        # print "added to %s dates, eventually flagged as malware. THERE SHOULD BE ZEROES" % looking_at_tld
        # hist = {}
        # for x in valid_data_points:
        #     hist[x] = hist.pop(x, 0) + 1
        # for k in sorted(hist.keys()):
        #     print k, hist[k]

        # print looking_at_tld
        # print len(valid_data_points)


def valid_ordering(azd_dates, malware_date):
    lowest_positive_delta = 9999
    lowest_azd_delta = None
    for d in azd_dates:
        delta = malware_date - d
        if delta.days < lowest_positive_delta and delta.days >= 0:
            lowest_azd_delta = d

    if lowest_azd_delta == None:
        return False

    return lowest_azd_delta

