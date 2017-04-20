
#!/bin/sh

cat delegated-ripencc-latest | awk 'BEGIN{FS="\|"; count24=0} $3 ~ /ipv4/ { num24 = $5/256 ;print ($4 "," $6 "," num24 ); count24 = count24 + num24} END{print("Total number of /24: " count24)}'
