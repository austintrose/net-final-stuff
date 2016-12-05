import pickle

biz_infile = open('./BIZ_ns_tox_datapoints')
biz_data = pickle.load(biz_infile)
biz_infile.close()

for ns, toxicity, malware_count in biz_data:
    print "NS: %s\tTox: %0.2f\tMalware #: %d" % (ns, toxicity, malware_count)
