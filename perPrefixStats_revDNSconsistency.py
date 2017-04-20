# -*- coding: utf-8 -*-
"""
Created on Thu Apr 20 09:53:42 2017

@author: sofiasilva
"""
"""
1. Generate per-prefix statistics 
1a. Latency in creating delegations (domain DB) OK
1b. Check how many networks have DNSSEC delegations (ds-rdata) (domain DB) OK
1c. Compute coverage of space with reverse delegations (percentage) (reverse-dns-consistency) OK
1d. Percentage of delegations with issues (lame) (reverse-dns-consistency) OK
2. Check what kind of issues (2nd stage) OK
3. And/or how many have signatures in the zone, but no rdata (2nd stage)
4. Number of delegations sharing the same nameservers (2nd stage) (reverse-dns) OK
4a. or a similar subset
5. Check if there is a correlation between the allocation date and the percentage of delegations with issues (Shane)

https://stat.ripe.net/data/reverse-dns-consistency/data.json?resource=193.0.0.0/21
https://stat.ripe.net/data/dns-check/data.json?get_results=true&resource=200.193.193.in-addr.arpa
"""

import urllib2, json
from ipaddress import ip_network
import pandas as pd
import math

revDNSconsistency_service = 'https://stat.ripe.net/data/reverse-dns-consistency'
dnsCheck_service = 'https://stat.ripe.net/data/dns-check'
del_file = '??' # TODO complete with file name 
del_columns = ['ip_version', 'network', 'count/prefLength', 'allocationDate', 'CC', 'opaque_id']

delegated_df = pd.read_csv(
                        del_file,
                        sep = '|',
                        header=None,
                        names = del_columns,
                        index_col=False,
                        parse_dates=['allocationDate'],
                        infer_datetime_format=True,
                        comment='#'
                    )

domainDB_file = './domainDB_data.csv'
domainDB_columns = ['domain', 'nameservers', 'creationDate', 'lastModifiedDate', 'hasDS-Rdata']
# domain,nserver,created,last-modified,ds-rdata(0/1)

domainDB_df = pd.read_csv(
                    domainDB_file,
                    sep = ',',
                    header = 0,
                    names = domainDB_columns,
                    index_col = False,
                    parse_dates = ['creationDate', 'lastModifiedDate'],
                    infer_datetime_format = True,
                    comment = '#')

issuesDict = dict()
nameserversDict = dict()
                    
for index, alloc_row in delegated_df.iterrows():
    if alloc_row['ip_version'] == 'ipv4':
        prefLen = 32 - int(math.log(alloc_row['count/prefLength'], 2))
        longestPref = 24
    else:
        prefLen = alloc_row['count/prefLength']
        longestPref = 64
        
    prefix = '{}/{}'.format(alloc_row['network'], prefLen)

    network = ip_network(unicode(prefix, 'utf-8'))
        
    url = '{}/data.json?resource={}'.format(revDNSconsistency_service, prefix)
    r = urllib2.urlopen(url)
    text = r.read()
    pref_dns_obj = json.loads(text)
    
    domains_list = pref_dns_obj['data']['prefixes'][alloc_row['ip_version']][prefix]['domains']
    
    # For IPv4 a unit is a /24 prefix. For IPv6 a unit is a /64 prefix.
    total_units = pow(2, longestPref - network.prefixlen)
    covered_units = 0
    units_with_issues = 0
    DNScheck = True
    dnssec_units = 0
    
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
            DNScheck = False
            break
        
        domain_subset = domainDB_df[domainDB_df['domain'] == domain]
        
        revDelLatency = (domain_subset['creationDate'] - alloc_row['allocationDate']).days
        
        nameservers_list = domain_subset['nameservers'].split()
        
        for nameserver in nameservers_list:
            if nameserver not in nameserversDict:
                nameserversDict[nameserver] = dict()
                nameserversDict[nameserver]['domains'] = [domain]
                nameserversDict[nameserver]['numOfUnits'] = units_covered_by_domain
            else:
                nameserversDict[nameserver]['domains'].append(domain)
                nameserversDict[nameserver]['numOfUnits'] += units_covered_by_domain
                
        if domain_subset['hasDS-Rdata'] == 1:
            dnssec_units += units_covered_by_domain
    
    coveragePercentage = 100*float(covered_units)/total_units
    issuesPercentage = 100*float(units_with_issues)/covered_units
    dnssecPercentage = 100*float(dnssec_units)/covered_units

    # TODO write line to csv file

    print '{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format(
                                                prefix,
                                                alloc_row['allocationDate'],
                                                alloc_row['ip_version'],
                                                alloc_row['CC'],
                                                alloc_row['opaque_id'],
                                                revDelLatency,
                                                coveragePercentage,
                                                issuesPercentage,
                                                dnssecPercentage,
                                                DNScheck,
                                                domain_subset['lastModifiedDate'])

print '---------------'
print 'issueType|numOfAppearences'
for issue_type in issuesDict:
    print '{}|{}'.format(issue_type, issuesDict[issue_type])

print '---------------'    
print 'nameserver|numOfDomains|unitsServedByNameserver'
for nameserver in nameserversDict:
    print '{}|{}|{}'.format(nameserver, len(nameserversDict[nameserver]['domains']), nameserversDict[nameserver]['numOfUnits'])

# TODO write nameserversDict to pickle file so that we have the list of domains for each nameserver?