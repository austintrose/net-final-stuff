import pickle
import numpy as np
from pylab import *

biz_infile = open('./biz_scatter_data', 'rb')
biz_data = pickle.load(biz_infile)

# "biz_data" is a list of dictionaries.
for b in biz_data:
    print b['registrar_name']
    print '\t', 'Good Domains:\t', b['good']
    print '\t', 'Bad Domains:\t', b['bad']
    print

# "com_data" is the same way, but I won't print them all because there's a ton
# com_infile = open('./com_scatter_data', 'rb')
# com_data = pickle.load(com_infile)
