#!/usr/bin/env python

import gzip
import re
import sys

def csv_output(o):
    print '{},"{}",{},{},{}'.format(
        o['domain'],
        ' '.join(o['nserver']),
        o['created'],
        o['last-modified'],
        '1' if o['ds-rdata'] else '0'
        )

def read_splitfile():
    with gzip.open('ripe.db.domain.gz') as g:
        for o in extract_objects(g):
            csv_output(o)

def extract_objects(fh):
    buffer = []
    for line in fh:
        if line == '\n':
            if buffer:
                yield parse_buffer(buffer)
                buffer = []
        elif line.startswith('#'):
            pass
        elif line.startswith(('+', '\t', ' ')):
            buffer[-1] = buffer[-1][:-1] + line[1:]
        else:
            buffer.append(line)
    # at the end of the file, yield the last object if there's one
    if buffer:
        yield parse_buffer(buffer)

def parse_buffer(buffer):
    o = { 'domain': '', 'nserver': [], 'ds-rdata': [], 'created': '', 'last-modified': '' }
    attr, _, value = buffer[0].partition(':')
    value = value.strip()
    o[attr] = value
    if attr == 'domain':
        value = value.lower()
        if value.endswith('.'):
            value = value.rstrip('.')
        o[attr] = value
        for x in buffer[1:]:
            attr, _, value = x.partition(':')
            if attr == 'nserver':
                ns = value.strip().lower().split()[0]
                if ns.endswith('.'):
                    ns.rstrip('.')
                o[attr].append(ns)
            elif attr == 'ds-rdata':
                o[attr].append(value.strip())
            elif attr in ('created', 'last-modified'):
                o[attr] = value.strip()
    return o

print 'domain,nserver,created,last-modified,ds-rdata'
read_splitfile()
