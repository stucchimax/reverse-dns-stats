#!/bin/sh

# fetch delegated file
# fetch split domain file

wget "ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
wget "ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.domain.gz"

# Get stats from delegated file

./parse_delegated.py > delegated_parsed.csv

# Get all the infos from the domain files

./parse_domain_splitfile.py > domains.csv

rm delegated-ripencc-extended-latest ripe.db.domain.gz

./perPrefixStats.py

./perPrefixStats_revDNSconsistency.py

./computeCorrelations.py

# tail -n+2 revDel_perPrefix_stats.csv | awk 'BEGIN{FS="|"; twentyfive = 0; fifty = 0; seventyfive = 0; hundred = 0;} {if ($5 <= 25) {twentyfive++;} else if (($5 > 25) && ($5 <= 50)) {fifty++;} else if (($5 > 50) && ($5 <= 75)) {seventyfive++;} else if (($5 > 75)) {hundred++;}} END{print(twentyfive " - " fifty " - " seventyfive " - " hundred);}'