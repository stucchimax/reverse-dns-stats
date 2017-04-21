#!/bin/sh

# fetch delegated file
# fetch split domain file

wget "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
wget "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.domain.gz"

# Get stats from delegated file

./parse_delegated > delegated_parsed.csv

# Get all the infos from the domain files

./parse_domain_splitfile.py > domains.csv

