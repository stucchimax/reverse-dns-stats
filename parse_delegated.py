#!/usr/bin/env python

with open('delegated-ripencc-extended-latest') as f:
    # throw away the first 4 header lines
    for i in range(4):
        f.next()
    for line in f:
        fields = line.strip().split('|')
        if fields[2] != 'asn' and fields[6] in ('allocated', 'assigned'):
            print ','.join((fields[2], fields[3], fields[4], fields[5], fields[1], fields[7]))
