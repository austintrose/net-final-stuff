import numpy as np
from pylab import *
import datetime

with open('BIZ_daily_additions.txt', 'r') as f:
    lines = f.readlines()

counts = []
for line in lines:
    date, count = line.split(' ')
    count = int(count)
    if count > 0:
        counts.append(count)

min_c = min(counts)
max_c = max(counts)
bins = 50
range_c = max_c - min_c
bin_width = range_c / float(bins)
xs = []
ys = []
for i in range(bins):
    begin = i*bin_width
    end = (i+1)*bin_width
    x = (end + begin) / 2.0
    in_bin = [i for i in counts if i >= begin and i < end]
    y = float(len(in_bin)) / len(counts)
    xs.append(x)
    ys.append(y)

plt.plot(xs, ys, 'b', linewidth=2)
plt.xlabel('BIZ domains added in a day', fontsize=14)
plt.ylabel('PDF', fontsize=14)
plt.show()

# plt.plot(
#     sorted_BIZ,
#     X_BIZ,
#     'b',
#     label='BIZ\t\t[%d points]' % len(BIZ_days_between),
#     linewidth=2)

# plt.xlabel('Days between registration and appearance', fontsize=14)
# plt.ylabel('Cumulative % of new malware domains', fontsize=14)
# plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
#            ['0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100'])
# plt.grid(True)
# plt.legend(loc=4)

# fig.savefig('days_between_registration_and_appearance.jpg')
