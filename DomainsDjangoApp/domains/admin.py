from django.contrib import admin
from .models import AddedZoneDomain, RemovedZoneDomain, Nameserver, AddedMalwareDomain, RemovedMalwareDomain

admin.site.register(AddedZoneDomain)
admin.site.register(RemovedZoneDomain)
admin.site.register(Nameserver)
admin.site.register(AddedMalwareDomain)
admin.site.register(RemovedMalwareDomain)
