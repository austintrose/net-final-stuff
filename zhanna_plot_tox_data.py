import pickle
import matplotlib.pyplot as plt

biz_infile = open('./BIZ_ns_tox_datapoints')
biz_data = pickle.load(biz_infile)
biz_infile.close()

sorted_by_toxicity = sorted(biz_data, key=lambda x: -x[1])

# for ns, toxicity, malware_count in biz_data:
#     print "NS: %s\tTox: %0.2f\tMalware #: %d" % (ns, toxicity, malware_count)

for ns, toxicity, malware_count in sorted_by_toxicity:
    print "NS: %s\tTox: %0.2f\tMalware #: %d" % (ns, toxicity, malware_count)

allns = [a[0] for a in sorted_by_toxicity]
alltox = [a[1] for a in sorted_by_toxicity]
allmalware = [a[2] for a in sorted_by_toxicity]

summalware = float(sum(allmalware))
cummalware = [float(100)*(float(allmalware[0])/summalware)]

for num in allmalware[1:]:
    cummalware.append(cummalware[-1] + float(100)*(float(num)/summalware))
    print cummalware[-1]

fig, ax = plt.subplots()
lineone = ax.plot((alltox), 'b--', linewidth = 3.0, label = 'Toxicity of the DNS server', clip_on=False)
#ax = fig.gca()
#ax.plot((alltox), "b-", clip_on=False)
ax.set_ylabel('Toxicity of the DNS server', color = 'b')
ax.set_xlabel('DNS Servers ordered by their toxicity')
ax.set_ylim(ymax = 130)
ax.set_xlim(xmax = len(alltox))
for tl in ax.get_yticklabels():
    tl.set_color('r')

#ax.set_xlim(xmin=0)


ax2 = ax.twinx()
linetwo = ax2.plot(cummalware, 'r-', linewidth = 3.0, label = 'Cumulative % of malware domains', clip_on=False)
ax2.set_ylabel('Cumulative % of malware domains', color='r')
ax2.set_ylim(ymax = 130)
ax2.set_xlim(xmax = len(alltox))
for tl in ax2.get_yticklabels():
        tl.set_color('r')

lines = lineone + linetwo
labs = [l.get_label() for l in lines]

plt.legend(lines,labs,loc = 1)

fig.savefig('biz_toxicity_plot.jpg')
