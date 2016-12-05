import pickle
import numpy as np
from pylab import *
import matplotlib.pyplot as plt

com_infile = open('./COM_scatter_data', 'rb')
com_data = pickle.load(com_infile)

#x axis is spammer domain counts
x = [line['bad'] for line in com_data]
#y axis is non-spammer domain counts
y = [line['good'] for line in com_data]

xmax =  max(x)
ymax =  max(y)

with open("com_registrars_top_ten.txt") as f:
    comreg = f.readlines()

for i,line in enumerate(comreg):
    comreg[i] = line.split('|',1)[0].strip()


minmaj = [b for b in com_data if b['bad'] > b['good']]
for entry in minmaj:
    print "More bad than good: "
    print entry['registrar_name']
    print "Good: " + str(entry['good'])
    print "Bad: " + str(entry['bad'])

labelreg = [b for b in com_data if b['registrar_name'] in comreg]

for b in labelreg:
    if 'PublicDomainRegistry' in b['registrar_name']:
        b['registrar_name'] = 'PublicDomainRegistry.com'

xrange = list(range(0, 10**4-1))
fig = plt.figure()
ax = fig.gca()
ax.scatter(x,y)
ax.plot((xrange), "r-", clip_on=False)
ax.set_yscale('symlog')
ax.set_xscale('symlog')
ax.set_ylim(ymin=0)
ax.set_xlim(xmin=0)
ax.set_xlim(xmax=10**4)
plt.ylabel('Non-malware domain dounts (log scale)')
plt.xlabel('Malware domain counts (log scale)')
xtext = []
anum = 0
for a in labelreg:
    if 'INTERNET DOMAIN SERVICE' in a['registrar_name']:
        xtext.append(a['bad']/100.0)
    elif 'DOMAIN.COM' in a['registrar_name']:
        xtext.append(a['bad']/50)
    elif 'Launchpad' in a['registrar_name']:
        xtext.append(a['bad']/35.0)
    elif 'WEST' in a['registrar_name']:
        xtext.append(a['bad']/3)
    elif 'ENOM' in a['registrar_name']:
        xtext.append(a['bad']*1)
    elif 'TUCOWS' in a['registrar_name']:
        xtext.append(a['bad']/5)
    elif 'PublicDomainRegistry' in a['registrar_name']:
        xtext.append(a['bad']/8)
    elif 'GODADDY' in a['registrar_name']:
        xtext.append(a['bad']/20)
    elif 'HICHINA' in a['registrar_name']:
        xtext.append(a['bad']/30)
    elif 'NETWORK SOLUTIONS' in a['registrar_name']:
        xtext.append(a['bad']/100)
    elif 'FastDomain' in a['registrar_name']:
        xtext.append(a['bad']/50)
    else:
        xtext.append(a['bad']/5)
ytext = []
for a in labelreg:    
    if 'Launchpad' in a['registrar_name']:
        ytext.append(a['good']/2000)
    elif 'WEST' in a['registrar_name']:
        ytext.append(a['good']/2000)
    elif 'ENOM' in a['registrar_name']:
        ytext.append(a['good']*1.5)
    elif 'TUCOWS' in a['registrar_name']:
        ytext.append(a['good']/1500)
    elif 'PublicDomainRegistry' in a['registrar_name']:
        ytext.append(a['good']/750)
    elif 'INTERNET DOMAIN SERVICE' in a['registrar_name']:
        ytext.append(a['good']/4500.0)
    elif 'GODADDY' in a['registrar_name']:
        ytext.append(a['good']*1.25)
    elif 'HICHINA' in a['registrar_name']:
        ytext.append(a['good']*3.5)
    elif 'NETWORK SOLUTIONS' in a['registrar_name']:
        ytext.append(a['good']*4)
    elif 'FastDomain' in a['registrar_name']:
        ytext.append(a['good']*5)
    elif 'DOMAIN.COM' in a['registrar_name']:
        ytext.append(a['good']/2)
    else:
        ytext.append(a['good']*3)
for registrar, xtextit, ytextit in zip(labelreg,xtext, ytext):
    plt.annotate(registrar['registrar_name'],xy = (registrar['bad'], registrar['good']),xytext =
       (xtextit, ytextit),color = 'gray', 
        arrowprops = dict(color = 'gray', arrowstyle = '-')) 


fig.savefig('com_registrar_scatter_plot.jpg')
# "com_data" is the same way, but I won't print them all because there's a ton
# com_infile = open('./com_scatter_data', 'rb')
# com_data = pickle.load(com_infile)
