#!/usr/bin/env python

import gzip
import logging
import re
import requests
import sys

def get_first_version(domain):
    global s
    query = 'http://rest.db.ripe.net/ripe/domain/{}/versions.json'.format(domain)
    try:
        timestamp = ''
        response = s.get(query)
        if response.ok:
            first_version = response.json()['versions']['version'][0]
            timestamp = first_version['date']
            logging.debug('%s', first_version)
    except Exception as e:
        logging.debug(e)
    return timestamp

def csv_output(o):
    if o['created'] == '1970-01-01T00:00:00Z':
        timestamp_from_versions = get_first_version(o['domain'])
        if timestamp_from_versions:
            o['timestamp-from-versions'] = timestamp_from_versions
    print '{},"{}",{},{},{},{}'.format(
        o['domain'],
        ' '.join(o['nserver']),
        '1' if o['ds-rdata'] else '0',
        o['created'],
        o['timestamp-from-versions'],
        o['last-modified']
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
    o = { 'domain': '', 'nserver': [], 'ds-rdata': [], 'created': '', 'timestamp-from-versions': '', 'last-modified': '' }
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

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
s = requests.Session()
print 'domain,nserver,ds-rdata,created,timestamp-from-versions,last-modified'
read_splitfile()
