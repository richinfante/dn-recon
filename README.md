# dn-recon
DNS enumeration using certificate transparency and dictionary bruteforce

## Sources of dictionary files
The SecLists Repo has many excellent subdomain lists ov various sizes:

https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

## Example Usage
```
python3 dn-recon.py -d altoromutual.com --discover

 ______  __   _      ______ _______ _______  _____  __   _
 |     \ | \  | ___ |_____/ |______ |       |     | | \  |
 |_____/ |  \_|     |    \_ |______ |_____  |_____| |  \_|

initial target: altoromutual.com
loaded 2 from certificate transparency
got 1 domains to explore
altoromutual.com A: 65.61.137.117
altoromutual.com NS: eur5.akam.net.
altoromutual.com NS: ns1-206.akam.net.
altoromutual.com NS: eur2.akam.net.
altoromutual.com NS: usc3.akam.net.
altoromutual.com NS: usw2.akam.net.
altoromutual.com NS: ns1-99.akam.net.
altoromutual.com NS: asia3.akam.net.
altoromutual.com NS: usc2.akam.net.
altoromutual.com SOA: asia3.akam.net. hostmaster.akamai.com. 1368446078 43200 7200 604800 86400
altoromutual.com TXT: "v=spf1 mx/24 -all"
111