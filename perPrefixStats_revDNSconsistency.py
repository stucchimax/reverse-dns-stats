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
https://stat.ripe.net/data/dns-check/data.json?get_results=true&resource=200.193.193.in-addr.arpa
"""

import urllib2, json
from ipaddress import ip_network

revDNSconsistency_service = 'https://stat.ripe.net/data/reverse-dns-consistency'
dnsCheck_service = 'https://stat.ripe.net/data/dns-check'

prefix = '193.0.0.0/21'
network = ip_network(unicode(prefix, 'utf-8'))

if network.version == 4:
    version_key = 'ipv4'
    longestPref = 24
else:
    version_key = 'ipv6'
    longestPref = 64

issuesDict = dict()

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
            domain_str = domain['domain']
            units_with_issues += units_covered_by_domain
            dnsCheck_url = '{}/data.json?get_results=true&resource={}'.format(dnsCheck_service, domain_str)
            r = urllib2.urlopen(dnsCheck_url)
            text = r.read()
            dns_check_obj = json.loads(text)
            results = dns_check_obj['data']['results']
            for result in results:
                if result['class'] == 'error':
                    if result['caption'] not in issuesDict:
                        issuesDict[result['caption']] = 1
                    else:
                        issuesDict[result['caption']] += 1
            
    except KeyError:
        noDNScheck = True
        break

coverage = 100*float(covered_units)/total_units
issuesPercentage = 100*float(units_with_issues)/covered_units