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
import os, sys
os.chdir(os.path.dirname(os.path.realpath(__file__)))
# Just for DEBUG
#os.chdir('/Users/sofiasilva/reverse-dns-stats')
import urllib2, json
import pandas as pd
import math
import pickle
from datetime import date


DEBUG = False

prefixStats_file = './revDel_perPrefix_stats.csv'
with open(prefixStats_file, 'wb') as stats:
    stats.write('Prefix|AllocationDate|IPversion|CC|Opaque_ID|RevDelLatency|RevDelCoveragePercentage|RevDelIssuesPercentage (From total covered)|RevDelWithDNSSECPercentage (From total covered)|hasDomainsWithNoDNScheck (bool)|lastModifiedDate|creationDateMayNotBeAccurate\n')

issuesStats_file = './revDel_issues_stats.csv'
with open(issuesStats_file, 'wb') as issues:
    issues.write('issueType|numOfAppearences\n')

nameserversStats_file = './revDel_nameservers_stats.csv'
with open(nameserversStats_file, 'wb') as nameserversStats:
    nameserversStats.write('nameserver|numOfDomains|unitsServedByNameserver(IPv4)|unitsServedByNameserver(IPv6)\n')
    
nameserversPickle = './revDel_domainsForNameservers.pkl'

revDNSconsistency_service = 'https://stat.ripe.net/data/reverse-dns-consistency'
dnsCheck_service = 'https://stat.ripe.net/data/dns-check'

del_file = './delegated_parsed.csv'
del_columns = ['ip_version',
               'network',
               'count/prefLength',
               'allocationDate',
               'CC',
               'opaque_id']

delegated_df = pd.read_csv(
                        del_file,
                        sep = ',',
                        header=None,
                        names = del_columns,
                        index_col=False,
                        parse_dates=['allocationDate'],
                        infer_datetime_format=True,
                        comment='#'
                    )

domainDB_file = './domains2.csv'
domainDB_columns = ['domain',
                    'nameservers',
                    'hasDS-Rdata',
                    'creationDate',
                    'dateFromVersion',
                    'lastModifiedDate']

domainDB_df = pd.read_csv(
                    domainDB_file,
                    sep = ',',
                    header = 0,
                    names = domainDB_columns,
                    index_col = False,
                    parse_dates = ['creationDate',
                                   'dateFromVersion',
                                   'lastModifiedDate'],
                    infer_datetime_format = True,
                    comment = '#')

issuesDict = dict()
nameserversDict = dict()
issuesPercentages = []
allocationAges = []
creationAges = []
lastModifiedAges = []
epoch = date(1970, 1, 1)


if DEBUG:
    delegated_df = delegated_df[(delegated_df['count/prefLength'] == 512) | (delegated_df['count/prefLength'] == 1024)].head(10)
                    
for index, alloc_row in delegated_df.iterrows():

    if alloc_row['ip_version'] == 'ipv4':
        prefLen = 32 - int(math.log(alloc_row['count/prefLength'], 2))
        longestPref = 24
    else:
        prefLen = alloc_row['count/prefLength']
        longestPref = 64
        
    prefix = '{}/{}'.format(alloc_row['network'], prefLen)

    sys.stderr.write('Starting to work with prefix {}\n'.format(prefix))
                
    url = '{}/data.json?resource={}'.format(revDNSconsistency_service, prefix)
    r = urllib2.urlopen(url)
    text = r.read()
    pref_dns_obj = json.loads(text)
    
    domains_list = pref_dns_obj['data']['prefixes'][alloc_row['ip_version']][prefix]['domains']
    
    # For IPv4 a unit is a /24 prefix. For IPv6 a unit is a /64 prefix.
    total_units = pow(2, longestPref - prefLen)
    covered_units = 0
    units_with_issues = 0
    hasDomainsWithNoDNScheck = False
    dnssec_units = 0
    domainsLastModifiedDates = []
    domainsCreationDates = []
    creationDateMayNotBeAccurate = False
    
    for domain in domains_list:
        domain_str = domain['domain']

        if DEBUG:
            sys.stderr.write('    Starting to work with domain {}\n'.format(domain_str))
            
        if domain['found']:
            if DEBUG:
                sys.stderr.write('    Domain {} found.\n'.format(domain_str))
            
            units_covered_by_domain = pow(2, longestPref - int(domain['prefix'].split('/')[1]))
            covered_units += units_covered_by_domain
            
            dnscheck = domain['dnscheck']
            if dnscheck is not None:
                dnscheck_status = dnscheck['status']
            
                if dnscheck_status == 'ERROR':
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
            else:
                hasDomainsWithNoDNScheck = True
        
            domain_subset_index_list = domainDB_df[domainDB_df['domain'] == domain_str].index
            
            if len(domain_subset_index_list) == 0:
                print domain_str
                continue
                # Although we are just processing those domains that have found = True,
                # this could happen if a domain object was deleted
            else:
                domain_subset_index = domain_subset_index_list[0]
                
            domain_row = domainDB_df.ix[domain_subset_index]
            
            domainsLastModifiedDates.append(domain_row['lastModifiedDate'].date())
            
            domainCreation = domain_row['creationDate'].date()

            dateFromVersion = domain_row['dateFromVersion']
            
            if domainCreation == epoch:
                if not dateFromVersion.isnull():
                    domainCreation = dateFromVersion.date()
                else:
                    domainCreation = domain_row['lastModifiedDate'].date()
                creationDateMayNotBeAccurate = True
                
            domainsCreationDates.append(domainCreation)
            
            nameservers_list = domain_row['nameservers'].split()
            
            for nameserver in nameservers_list:
                if nameserver not in nameserversDict:
                    nameserversDict[nameserver] = dict()
                    nameserversDict[nameserver]['domains'] = [domain]
                    if alloc_row['ip_version'] == 'ipv4':
                        nameserversDict[nameserver]['numOfUnits_IPv4'] = units_covered_by_domain
                    else:
                        nameserversDict[nameserver]['numOfUnits_IPv6'] = units_covered_by_domain
                        
                else:
                    nameserversDict[nameserver]['domains'].append(domain)
                    if alloc_row['ip_version'] == 'ipv4':
                        nameserversDict[nameserver]['numOfUnits_IPv4'] += units_covered_by_domain
                    else:
                        nameserversDict[nameserver]['numOfUnits_IPv6'] += units_covered_by_domain
    
                    
            if domain_row['hasDS-Rdata'] == 1:
                dnssec_units += units_covered_by_domain
                
        elif DEBUG:
            sys.stderr.write('    Domain {} not found.\n'.format(domain_str))
        
    allocDate = alloc_row['allocationDate'].date()
    allocationAges.append((allocDate-epoch).days)

    if len(domainsCreationDates) > 0:
        domainCreation = min(domainsCreationDates)
    else:
        domainCreation = epoch
        
    creationAges.append((domainCreation-epoch).days)
    
    revDelLatency = (domainCreation - allocDate).days

    if len(domainsLastModifiedDates) > 0:
        lastModified = max(domainsLastModifiedDates)
    else:
        lastModified = epoch
        
    lastModifiedAges.append((lastModified-epoch).days)
    
    if total_units != 0:
        coveragePercentage = 100*float(covered_units)/total_units
    else:
        coveragePercentage = -1
        
    if covered_units != 0:
        issuesPercentage = 100*float(units_with_issues)/covered_units
        dnssecPercentage = 100*float(dnssec_units)/covered_units
    else:
        if units_with_issues == 0:
            issuesPercentage = 0
        else:
            issuesPercentage = -1
            
        if dnssec_units == 0:
            dnssecPercentage = 0
        else:
            dnssecPercentage = -1
    
    issuesPercentages.append(issuesPercentage)

    with open(prefixStats_file, 'a') as stats:
        stats.write('{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n'.format(
                                                prefix,
                                                alloc_row['allocationDate'],
                                                alloc_row['ip_version'],
                                                alloc_row['CC'],
                                                alloc_row['opaque_id'],
                                                revDelLatency,
                                                coveragePercentage,
                                                issuesPercentage,
                                                dnssecPercentage,
                                                hasDomainsWithNoDNScheck,
                                                lastModified,
                                                creationDateMayNotBeAccurate))
                                                

with open(issuesStats_file, 'a') as issues:
    for issue_type in issuesDict:
        issues.write('{}|{}\n'.format(issue_type, issuesDict[issue_type]))

with open(nameserversStats_file, 'a') as nameserversStats:
    for nameserver in nameserversDict:
        if 'numOfUnits_IPv4' in nameserversDict[nameserver]:
            units_ipv4 = nameserversDict[nameserver]['numOfUnits_IPv4']
        else:
            units_ipv4 = 0
        
        if 'numOfUnits_IPv6' in nameserversDict[nameserver]:
            units_ipv6 = nameserversDict[nameserver]['numOfUnits_IPv6']
        else:
            units_ipv6 = 0
            
        nameserversStats.write('{}|{}|{}|{}\n'.format(nameserver,
                                                       len(nameserversDict[nameserver]['domains']),
                                                        units_ipv4, units_ipv6))

with open(nameserversPickle , 'wb') as f:
    pickle.dump(nameserversDict, f, pickle.HIGHEST_PROTOCOL)

issuesPercentagesPickle = './issuesPercentages.pkl'
with open(issuesPercentagesPickle, 'wb') as f:
    pickle.dump(issuesPercentages, f, pickle.HIGHEST_PROTOCOL)

creationAgesPickle = './creationAges.pkl'
with open(creationAgesPickle, 'wb') as f:
    pickle.dump(creationAges, f, pickle.HIGHEST_PROTOCOL)

lastModAgesPickle = './lastModAges.pkl'
with open(lastModAgesPickle , 'wb') as f:
    pickle.dump(lastModifiedAges, f, pickle.HIGHEST_PROTOCOL)

allocAgesPickle = './allocAges.pkl'
with open(allocAgesPickle , 'wb') as f:
    pickle.dump(allocationAges, f, pickle.HIGHEST_PROTOCOL)