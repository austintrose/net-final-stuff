from django.db import models

class WhoisQuery(models.Model):
    domain_name = models.CharField(max_length=300)
    registrar = models.CharField(max_length=300)
    country = models.CharField(max_length=20)
    creation = models.DateField('date assigned')

    class Meta:
        unique_together = (("domain_name", "creation", "country", "registrar"),)

class Nameserver(models.Model):
    name = models.CharField(max_length=300)
    assigned = models.DateField('date assigned')

    def __str__(self):
        return "%s %s" % (self.name, str(self.assigned))

    class Meta:
        unique_together = (("name", "assigned"),)

class AddedZoneDomain(models.Model):
    tld = models.CharField(max_length=3)
    name = models.CharField(max_length=300)
    added = models.DateField('date added')

    nameservers = models.ManyToManyField(Nameserver, "added_domains")

    def __str__(self):
        return "%s %s %s" % (self.tld, self.name, str(self.added))

    class Meta:
        unique_together = (("tld", "name", "added"),)
    
class RemovedZoneDomain(models.Model):
    tld = models.CharField(max_length=3)
    name = models.CharField(max_length=300)
    removed = models.DateField('date removed')

    nameservers = models.ManyToManyField(Nameserver, "removed_domains")

    def __str__(self):
        return "%s %s %s" % (self.tld, self.name, str(self.removed))

    class Meta:
        unique_together = (("tld", "name", "removed"),)

class AddedMalwareDomain(models.Model):
    tld = models.CharField(max_length=3)
    name = models.CharField(max_length=300)
    added = models.DateField('date added')

    def __str__(self):
        return "%s %s %s" % (self.tld, self.name, str(self.added))

    class Meta:
        unique_together = (("tld", "name", "added"),)

class RemovedMalwareDomain(models.Model):
    tld = models.CharField(max_length=3)
    name = models.CharField(max_length=300)
    removed = models.DateField('date removed')

    def __str__(self):
        return "%s %s %s" % (self.tld, self.name, str(self.removed))

    class Meta:
        unique_together = (("tld", "name", "removed"),)
