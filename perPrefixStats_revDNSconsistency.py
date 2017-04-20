# -*- coding: utf-8 -*-
"""
Created on Thu Apr 20 09:53:42 2017

@author: sofiasilva
"""
"""
1. Generate per-prefix statistics 
1a. Latency in creating delegations (reverse-dns)
1b. Compute coverage of space with reverse delegations (reverse-dns-consistency)
1c. Number of delegations with issues (lame) (reverse-dns-consistency)
1d. Check how many networks have DNSSEC delegations (ds-rdata) (reverse-dns)

https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=193.0.0.0/21
"""

import urllib2, json
from ipaddress import ip_network

revDNSconsistency_service = 'https://stat.ripe.net/data/reverse-dns-consistency'
prefix = '193.0.0.0/21'
network = ip_network(unicode(prefix, 'utf-8'))

if network.version == 4:
    version_key = 'ipv4'
    longestPref = 24
else:
    version_key = 'ipv6'
    longestPref = 64

url = '{}/data.json?resource={}'.format(revDNSconsistency_service, prefix)
r = urllib2.urlopen(url)
text = r.read()
pref_dns_obj = json.loads(text)

domains_list = pref_dns_obj['data']['prefixes'][version_key][prefix]['domains']

# For IPv4 a unit is a /24 prefix. For IPv6 a unit is a /64 prefix.
total_units = pow(2, longestPref - network.prefixlen)
covered_units = 0
units_with_issues = 0
noDNScheck = False

for domain in domains_list:
    domain_network = ip_network(domain['prefix'])
    units_covered_by_domain = pow(2, longestPref - domain_network.prefixlen)
    covered_units += units_covered_by_domain
    
    try:    
        dnscheck_status = domain['dnscheck']['status']
        if dnscheck_status == 'ERROR':
            units_with_issues += units_covered_by_domain
    except KeyError:
        noDNScheck = True
        break

coverage = 100*float(covered_units)/total_units
issuesPercentage = 100*float(units_with_issues)/covered_units


