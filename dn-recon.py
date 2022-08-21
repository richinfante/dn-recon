import requests
import dns.resolver
import argparse

# ref: https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
class TermColor:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKCYAN = '\033[96m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

TYPES = [
  'A',
  'A6',
  'AAAA',
  'AFSDB',
  # 'ANY',
  'APL',
  # 'AXFR',
  'CAA',
  'CDNSKEY',
  'CDS',
  'CERT',
  'CNAME',
  'CSYNC',
  'DHCID',
  'DLV',
  'DNAME',
  'DNSKEY',
  'DS',
  'EUI48',
  'EUI64',
  'GPOS',
  'HINFO',
  'HIP',
  'IPSECKEY',
  'ISDN',
  # 'IXFR',
  'KEY',
  'KX',
  'LOC',
  # 'MAILA',
  # 'MAILB',
  'MB',
  'MD',
  'MF',
  'MG',
  'MINFO',
  'MR',
  'MX',
  'NAPTR',
  'NONE',
  'NS',
  # 'NSAP-PTR',
  'NSAP',
  'NSEC',
  'NSEC3',
  'NSEC3PARAM',
  'NULL',
  'NXT',
  # 'OPT',
  'PTR',
  'PX',
  'RP',
  # 'RRSIG',
  'RT',
  'SIG',
  'SOA',
  'SPF',
  'SRV',
  'SSHFP',
  'TA',
  # 'TKEY',
  'TLSA',
  # 'TSIG',
  'TXT',
  'UNSPEC',
  'URI',
  'WKS',
  'X25',
]

print(f"""{TermColor.OKGREEN}
 ______  __   _      ______ _______ _______  _____  __   _
 |     \ | \  | ___ |_____/ |______ |       |     | | \  |
 |_____/ |  \_|     |    \_ |______ |_____  |_____| |  \_|
{TermColor.ENDC}""")


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-d', dest='domain', help='domain for scanning', required=True)
parser.add_argument('--discover', dest='discover', action='store_true', help='Enable subdomain discovery via certificate transparency logs')
parser.add_argument('--key', dest='api_key', help='SSLMate Certspotter certificate transparency log API key')
parser.add_argument('--dictfile', dest='dict_file', help='Add subdomains from a dictionary file')
parser.add_argument('-v|--verbose', dest='verbose', action='store_true', help='Show additional error messaging during scan')

args = parser.parse_args()

domain = args.domain

print(f"initial target: {domain}")

# Add found target subdomains to target list
targets = set()
targets.add(domain)

# allow skipping of discovery
if args.discover:
  headers={}
  # use api key if found
  if args.api_key:
    headers['Authorization'] = f'Bearer {args.api_key}'

  # call certspotter API to get all issuances
  certs = requests.get(f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&match_wildcards=true&expand=issuer&expand=dns_names', headers=headers, timeout=10)
  cert_info = certs.json()
  if not certs.ok:
    print(f"{TermColor.FAIL}{TermColor.BOLD}Error:{TermColor.ENDC} {cert_info.get('code')}: {cert_info.get('message')}")
    exit(1)

  # Add discovered hosts to targets
  out_certs = set()
  for target in cert_info:
    for dns_name in target['dns_names']:
      out_certs.add(dns_name)
  print(f'loaded {len(out_certs)} from certificate transparency')

  targets.union(out_certs)
else:
  print('skipping certificate transparency domain enumeration.')

# allow loading domains from dictfile
if args.dict_file:
  dict_file = open(args.dict_file, 'r')
  subdomains = dict_file.read().split('\n')
  for subdomain in subdomains:
    subdomain = subdomain.strip().strip('.') # strip leading whitespace, and leading/trailing dots
    if subdomain:
      targets.add(f'{subdomain}.{domain}')

  print(f'loaded {len(subdomains)} from dictfile')

# print info
print(f'got {len(targets)} domains to explore')

targets_to_search = sorted(targets)

# run enumeration
for target in targets_to_search:
  for rec_type in TYPES:
    try:
      answers = dns.resolver.resolve(target, rec_type)
    except dns.resolver.NoAnswer:
      # print(rec_type, ':', 'NO_DATA')
      continue
    except dns.resolver.NoNameservers:
      print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {TermColor.FAIL}ERROR{TermColor.ENDC}: NO_NAMESERVERS")
      break
    except dns.resolver.LifetimeTimeout:
      print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {TermColor.FAIL}ERROR{TermColor.ENDC}: TIMEOUT")
      continue
    except dns.resolver.NoMetaqueries as e:
      print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {TermColor.FAIL}ERROR{TermColor.ENDC}: ERR_NO_META")
      continue
    except dns.resolver.NXDOMAIN:
      if args.verbose:
        print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {TermColor.FAIL}ERROR{TermColor.ENDC}: NXDOMAIN")
      break
    except Exception as err:
      print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {TermColor.FAIL}ERROR{TermColor.ENDC}: {err}")

    for rdata in answers:
      print(f"{TermColor.BOLD}{target}{TermColor.ENDC} {TermColor.OKBLUE}{rec_type}{TermColor.ENDC}: {rdata.to_text()}")