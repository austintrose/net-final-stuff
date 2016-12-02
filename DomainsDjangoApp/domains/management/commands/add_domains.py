import os
import datetime
import re

from django.core.management.base import BaseCommand, CommandError
from domains.models import AddedZoneDomain, RemovedZoneDomain, Nameserver

COM_DIFF_DIR = '/home/atrose/COM_DIFF/'

COM_DIFF_FILES = ['filtered.20160304_20160305.diff', 'filtered.20160508_20160509.diff', 'filtered.20160403_20160404.diff', 'filtered.20160329_20160330.diff', 'filtered.20160513_20160514.diff', 'filtered.20160518_20160519.diff', 'filtered.20160324_20160325.diff', 'filtered.20160627_20160628.diff', 'filtered.20160622_20160623.diff', 'filtered.20160114_20160115.diff', 'filtered.20160607_20160608.diff', 'filtered.20160119_20160120.diff', 'filtered.20160413_20160414.diff', 'filtered.20160203_20160204.diff', 'filtered.20160124_20160125.diff', 'filtered.20160503_20160504.diff', 'filtered.20160314_20160315.diff', 'filtered.20160309_20160310.diff', 'filtered.20160104_20160105.diff', 'filtered.20160612_20160613.diff', 'filtered.20160428_20160429.diff', 'filtered.20160523_20160524.diff', 'filtered.20160418_20160419.diff', 'filtered.20160223_20160224.diff', 'filtered.20160228_20160229.diff', 'filtered.20160218_20160219.diff', 'filtered.20160108_20160109.diff', 'filtered.20160212_20160213.diff', 'filtered.20160527_20160528.diff', 'filtered.20160402_20160403.diff', 'filtered.20160207_20160208.diff', 'filtered.20160318_20160319.diff', 'filtered.20160422_20160423.diff', 'filtered.20160507_20160508.diff', 'filtered.20160128_20160129.diff', 'filtered.20160123_20160124.diff', 'filtered.20160616_20160617.diff', 'filtered.20160626_20160627.diff', 'filtered.20160611_20160612.diff', 'filtered.20160103_20160104.diff', 'filtered.20160517_20160518.diff', 'filtered.20160313_20160314.diff', 'filtered.20160118_20160119.diff', 'filtered.20160502_20160503.diff', 'filtered.20160522_20160523.diff', 'filtered.20160606_20160607.diff', 'filtered.20160113_20160114.diff', 'filtered.20160328_20160329.diff', 'filtered.20160303_20160304.diff', 'filtered.20160512_20160513.diff', 'filtered.20160202_20160203.diff', 'filtered.20160227_20160228.diff', 'filtered.20160621_20160622.diff', 'filtered.20160308_20160309.diff', 'filtered.20160417_20160418.diff', 'filtered.20160427_20160428.diff', 'filtered.20160412_20160413.diff', 'filtered.20160323_20160324.diff', 'filtered.20160515_20160516.diff', 'filtered.20160620_20160621.diff', 'filtered.20160516_20160517.diff', 'filtered.20160210_20160211.diff']

mysql_log = '/home/atrose/log'

def log(s):
    with open(mysql_log, "a") as myfile:
        myfile.write(s)

class Command(BaseCommand):
    def handle(self, *args, **options):

        for i in range(len(COM_DIFF_FILES))[::2]:
            if (os.fork() == 0):
                how_many_to_handle = min(2, len(COM_DIFF_FILES) - i)
                for x in range(how_many_to_handle):
                    log("COM " + COM_DIFF_FILES[i+x] + "\n")
                    self.handle_com_file(COM_DIFF_FILES[i+x])
                exit(0)

    def handle_com_file(self, file_name):
        if file_name.find('filtered') != 0:
            print "Error", file_name
            exit(1)

        underscore_index = file_name.index('_')
        diff_index = file_name.find('diff')
        date_string = file_name[underscore_index+1:diff_index-1]
        date = datetime.datetime.strptime(date_string, "%Y%m%d").date()

        with open(COM_DIFF_DIR + file_name, 'r') as f:
            for line in f.readlines():
                split = line.split(' ')
                if len(split) != 4:
                    print "Error", split
                    exit(1)
                diff_type, domain, _, nameserver = line.split(' ')

                # Don't have trailing period.
                p = re.compile("\.$")
                for m in p.finditer(nameserver):
                    nameserver = nameserver[:m.start()]
                    break

                while (True):
                    try:
                        # Add nameserver.
                        nameserver_instance, _ = Nameserver.objects.get_or_create(name=nameserver.upper(), assigned=date)
                        break
                    except Exception:
                        pass

                if diff_type == ">":
                    while (True):
                        try:
                            added_instance, _ = AddedZoneDomain.objects.get_or_create(tld="COM", name=domain.upper(), added=date)
                            added_instance.nameservers.add(nameserver_instance)
                            added_instance.save()
                            break
                        except Exception:
                            pass

                elif diff_type == "<":
                    while (True):
                        try:
                            removed_instance, _ = RemovedZoneDomain.objects.get_or_create(tld="COM", name=domain.upper(), removed=date)
                            removed_instance.nameservers.add(nameserver_instance)
                            removed_instance.save()
                            break
                        except Exception:
                            pass


