import pickle
import numpy as np
from pylab import *
import matplotlib.pyplot as plt

biz_infile = open('./biz_scatter_data', 'rb')
biz_data = pickle.load(biz_infile)

#x axis is spammer domain counts
x = [line['bad'] for line in biz_data]
#y axis is non-spammer domain counts
y = [line['good'] for line in biz_data]

xmax =  max(x)
ymax =  max(y)

with open("biz_registrars_top_ten.txt") as f:
    bizreg = f.readlines()

for i,line in enumerate(bizreg):
    bizreg[i] = line.split('|',1)[0].strip()

for line in bizreg:
    print line

labelreg = [b for b in biz_data if b['registrar_name'] in bizreg]

for b in labelreg:
    if 'PUBLICDOMAINREGISTRY' in b['registrar_name']:
        b['registrar_name'] = 'PUBLICDOMAINREGISTRY.COM'

xrange = list(range(0, 10**2-1))
fig = plt.figure()
ax = fig.gca()
ax.scatter(x,y)
ax.plot((xrange), "r-", clip_on=False)
ax.set_yscale('symlog')
ax.set_xscale('symlog')
ax.set_ylim(ymin=0)
ax.set_xlim(xmin=0)
ax.set_xlim(xmax=10**2)
plt.ylabel('Non-malware domain dounts (log scale)')
plt.xlabel('Malware domain counts (log scale)')
xtext = []
for a in labelreg:
    if a['good'] < 10**3:
        xtext.append(a['bad'] + a['bad']/5)
    elif 'PUBLICDOMAINREGISTRY' in a['registrar_name']:
        xtext.append(a['bad']/15)
    elif 'ENOM' in a['registrar_name']:
        xtext.append(a['bad'] + a['bad']/5)
    elif 'BIZCN' in a['registrar_name']:
        xtext.append(a['bad']/10)
    elif 'TUCOWS' in a['registrar_name']:
        xtext.append(a['bad'] - a['bad']/3)
    elif 'NAMECHEAP' in a['registrar_name']:
        xtext.append(a['bad']/2)
    elif 'GODADDY' in a['registrar_name']:
        xtext.append(a['bad']/4)
    elif a['good'] > 10**4:
        xtext.append(a['bad'] / 10 )
    else:
        xtext.append(a['bad']/5)
ytext = []
for a in labelreg:    
    if a['good'] <= 10**3:
        ytext.append(a['good']/2 )
    elif 'ENOM' in a['registrar_name']:
        ytext.append(a['good']/2)
    elif 'TUCOWS' in a['registrar_name']:
        ytext.append(a['good'] + a['good']/3)
    elif 'NAMECHEAP' in a['registrar_name']:
        ytext.append(a['good'] * 3)
    elif 'GODADDY' in a['registrar_name']:
        ytext.append(a['good']*5)
    elif a['good'] <= 1.5*10**3:
        ytext.append(a['good']*2)
    elif a['good'] < 0.5*10**4:
        ytext.append(a['good']*5)
    else:
        ytext.append(a['good']*3)
for registrar, xtextit, ytextit in zip(labelreg,xtext, ytext):
    plt.annotate(registrar['registrar_name'],xy = (registrar['bad'], registrar['good']),xytext =
       (xtextit, ytextit),color = 'gray', 
        arrowprops = dict(color = 'gray', arrowstyle = '-')) 
#plt.show()


fig.savefig('biz_registrar_scatter_plot.jpg')
# "com_data" is the same way, but I won't print them all because there's a ton
# com_infile = open('./com_scatter_data', 'rb')
# com_data = pickle.load(com_infile)
