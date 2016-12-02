import os
import datetime
import re

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain, 
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

class Command(BaseCommand):
    def handle(self, *args, **options):
        log = open('/home/atrose/log', 'w')
        for azd in AddedZoneDomain.objects.all():
            matches = AddedMalwareDomain.objects.filter(name=azd.name, tld=azd.tld)
            if matches.count() > 0:
                line = "name=%s, pk=%d\n" % (azd.name, azd.pk)
                log.write(line)
                print line,
