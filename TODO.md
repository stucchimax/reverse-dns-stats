

1. Generate per-prefix statistics 
1a. Latency in creating delegations (domain DB)
1b. Check how many networks have DNSSEC delegations (ds-rdata) (domain DB) 
1c. Compute coverage of space with reverse delegations (percentage) (reverse-dns-consistency)
1d. Percentage of delegations with issues (lame) (reverse-dns-consistency)
2. Check what kind of issues (2nd stage)
3. And/or how many have signatures in the zone, but no rdata (2nd stage)
4. Number of delegations sharing the same nameservers (2nd stage) (reverse-dns)
4a. or a similar subset


