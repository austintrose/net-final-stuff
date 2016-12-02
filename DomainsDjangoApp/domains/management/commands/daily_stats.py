# TODO: Figure out how many COM domains added in each day,
# look at the distribution, see if you can model it, and see if
# domains registered on outlier days are more likely to be malware

import os
import datetime
import re
from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from domains.models import (AddedZoneDomain, RemovedZoneDomain,
                            Nameserver, AddedMalwareDomain, RemovedMalwareDomain)

class Command(BaseCommand):
    def handle(self, *args, **options):
        pass
