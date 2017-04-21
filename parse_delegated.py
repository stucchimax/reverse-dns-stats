#!/usr/bin/env python

import csv
import gzip

with open('delegated-ripencc-extended-latest', 'rb') as f:
    reader = csv.reader(f, delimiter='|')
    for line in reader:
        if line[2] != 'asn' and (line[6] == "allocated" or line[6] == "assigned"):
            print ("{},{},{},{},{},{}").format(line[2], line[3], line[4], line[5], line[1], line[7]);
        
        