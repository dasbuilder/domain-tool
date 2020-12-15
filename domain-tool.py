#!/usr/local/bin python3

# Version 2.0

import sys, os
import subprocess
import requests
import argparse
import re
from collections import defaultdict

argv = sys.argv

# These are here for reasons...
check_output = subprocess.check_output
PIPE = subprocess.PIPE
run = subprocess.run
Popen = subprocess.Popen


class Digger:

    '''
    Digger class
    '''

    def __init__(self, domain):
        self._domain = domain
        self._dig_prefix = ['dig', '+short']

    def _dig_text(self, record_type):
        return self._dig_prefix + [record_type, self._domain]

    def _digger(self, record_type):
        return run(self._dig_text(record_type), capture_output=True,
                   encoding='unicode_escape')

    def stdout(self, record_type):
        final_record = self._digger(record_type)
        return final_record.stdout


class WhoisCheck:

    '''
    WhoisCheck class
    '''

    def __init__(self, domain):
        self.domain = domain
        self.tld_regex = re.compile(r'refer:\s?(.*)')
        self.registered_domain_regex = re.compile("(Registrar: |Registrar \
            Name: |Registrar URL: |Updated Date: |Creation Date: |(Expiration|Expiry) Date: ).*", re.M)
        self.unregistered_domain_regex = re.compile('(No match for domain|Domain not found)')

    # using the following to look up the refer TLD
    def _tld_text(self):
        return ['whois', '-I', self.domain]

    # doing the subprocess run.
    def _tld_check(self):
        return run(self._tld_text(),
                   capture_output=True, encoding='unicode_escape')

    # Searching the stdout from above for the right info
    def _tld_search(self):
        _tld_regex = self.tld_regex.search(self._tld_check().stdout)
        if _tld_regex.group:
            return _tld_regex.group()
        else:
            print('Some type of way')

    # Lastly, sub the spaces out
    def _tld_space_replace(self):
        return re.sub(r'refer:\s+', '', self._tld_search())

    # Now we can continue running our whois like normal, but with the -h flag. 
    # Returns "whois domain"
    def _whois_text(self):
        return ['whois', '-h', self._tld_space_replace(), self.domain]

    # Not checking output because we want to manually verify
    # non-zero exit status.
    def _whois(self):
        return run(self._whois_text(), capture_output=True,
                   encoding='unicode_escape')

    def _domain_is_registered(self):
        if self._whois().returncode == 1:
            return self._whois().stdout
        elif self._whois().returncode == 0:
            not_found_check = self.unregistered_domain_regex.findall(
                    self._whois().stdout)
            if not_found_check:
                return not_found_check
            else:
                return self._whois().stdout

    # We're not actually checking for an error but if the
    # domain is not registered.
    def _whois_regcheck(self):
        if 'Domain not found' in self._domain_is_registered():
            return None
        else:
            return [matches.group() for matches in
                    self.registered_domain_regex.finditer(
                        self._domain_is_registered())]

    def _whois_dict(self):
        # This helped out
        # https://stackoverflow.com/questions/59483010/add-a-list-to-a-dictionary-key-within-a-for-loop-with-an-undefined-key
        self.whois_dict = defaultdict(list)
        regcheck = self._whois_regcheck()
        if not regcheck:
            return f'{self.domain} may not be registered. Please manually run\
"whois {self.domain}" for more information'
        else:
            for names in regcheck:
                self.whois_dict[names.split(':')[0]].append(names)
            return self.whois_dict


# Formatter for SOA record
def soa_formatter(soa):
    soa = tuple(soa.split(' '))
    return f'''Primary Nameserver: {soa[0]}
Responsible Party: {soa[1]}
Serial Number: {soa[2]}
Refresh: {soa[3]}
Retry: {soa[4]}
Expire: {soa[5]}
TTL: {soa[6]}
'''


def whois_formatter(whois):
    values = sorted([whois[keys][0] for keys in whois])
    return f'''{values[0]}
{values[1]}
{values[2]}
{values[3]}
{values[4]}
'''


def cdn_check(args):

    # Takes in the Digger class for domain name

    # Takes in the Digger class for domain name

    headers = {'user-agent': 'curl/7.54.0'}
    cdn_url = os.environ.get('CDNCHECK')
    # Uses argparse and passes that to Dig's _domain
    domain = args._domain
    base_url = f'http://{domain}/{cdn_url}'
    site_name = os.environ.get('SITE')
    server = os.environ.get('CID')
    cdn_req = requests.get(base_url, headers=headers)

    if site_name not in cdn_req.headers:
        err = requests.exceptions.HTTPError("404 - Not Found",
                                            cdn_req.status_code)
        return f"{err.strerror}\t{err.errno}\n"
    else:
        _output = [cdn_req.headers[site_name],
                   cdn_req.headers[server]]
        return f"Site: {_output[0]}\nServer: {_output[1]}\n"


def is_protocol(domain):
    proto_match = re.compile(r'^(https?:\/\/)')
    trailing_slash = re.compile(r'.*(\/)$')
    if proto_match.match(domain):
        domain = proto_match.sub('', domain)
    if trailing_slash.match(domain):
        domain = domain.strip(trailing_slash.match(domain).group(1))
    return domain


def default_records(dig, record_type):
    # A record
    print('-- A record(s) --')
    print(dig.stdout(record_type[0]))

    print("-- HostCheck --")
    cdn_check(dig)

    print('-- CNAME record(s) --')
    print(dig.stdout(record_type[2]))

    print('-- Nameservers --')
    print(dig.stdout(record_type[4]))


def detailed_records(dig, record_type):
    whois_raw = WhoisCheck(dig._domain)
    print('-- A record(s) --')
    print(dig.stdout(record_type[0]))

    print("-- HostCheck --")
    print(cdn_check(dig))

    print('-- IPv6 record(s) --')
    print(dig.stdout(record_type[1]))

    print('-- CNAME record(s) --')
    print(dig.stdout(record_type[2]))

    print('-- MX record(s) --')
    print(dig.stdout(record_type[3]))

    print('-- Nameservers --')
    print(dig.stdout(record_type[4]))

    print('-- SOA record(s) --')
    print(soa_formatter(dig.stdout(record_type[5])))

    print('-- TXT Record(s) --')
    print(dig.stdout(record_type[6]))

    print('-- WHOIS Info --')
    print(whois_formatter(whois_raw._whois_dict()))


# SSL section
# Gets the SSL information via subprocess
def ssl(domain):

    open_ssl = Popen(['openssl', 's_client', '-verify', '5', '-connect',
                      f'{domain}:443', '-servername', f'{domain}'],
                     stdout=PIPE, stdin=subprocess.DEVNULL, 
                     stderr=subprocess.DEVNULL)

    ssl_check = Popen(['openssl', 'x509', '-noout', '-text'],
                      stdin=open_ssl.stdout, stdout=PIPE)

    ssl_out = ssl_check.communicate()[0]
    ssl_info = sorted(re.findall(
        r'DNS:.*|Not After.*|Not Before.*|Serial Number\W\n.*',
        ssl_out.decode('utf-8')))
    return ssl_info


def ssl_text(ssl_info):
    ssl_dom = re.sub('DNS:', '', ssl_info[0])
    ssl_start = ssl_info[2].replace('Not Before: ', '')
    ssl_expiry = ssl_info[1].replace('Not After : ', '')
    ssl_sn = re.sub(r'Serial Number:\n\s+(\w.+)', '\\1', ssl_info[3])
    return ssl_dom, ssl_start, ssl_expiry, ssl_sn


def ssl_debug(domain):
    return f'''Run the following command: 
    openssl s_client -verify 5 -connect {domain}:443 -servername {domain} </dev/null 2>/dev/null | 
    openssl x509 -noout -text | egrep 'DNS:.*|Not After.*|Not Before.*|Serial Number\W\\n.*'
    '''


def ssl_details(ssl_text, domain):
    print(f'\nSSL report for {domain}\n')
    print('-- SSL Domain --')
    print(domain)
    print('-- SSL Began --')
    print(ssl_text[2])
    print('-- SSL Expiry --')
    print(ssl_text[1])
    print('-- SSL Cert Serial Number --')
    print(ssl_text[3])


def usage():
    print('''
                    ========== DNS Check Tool ==========
                            by Spencer Anderson

            Retreives DNS, SSL and WHOIS information for a domain name.
            Without any args, dnscheck will return any A, CNAME, nameservers as well as, 
            which site and server the site is hosted on.


            Accepts domains and subdomains with protocol and trailing slash. 

Usage: dnscheck.py [-h] [--help] | domain [details] [cdn] [ssl] 
    dnscheck.py https://domain.com/ 
    dnscheck.py domain.com details
    dnscheck.py domain.com ssl
''')


def arg_parser():
    # Top level parser
    description_text = 'Easily checks DNS records, including CDN for server and site name.'
    parser = argparse.ArgumentParser(prog='DNSCheck',
                                     description=description_text,
                                     add_help=False)
    parser.add_argument('domain', type=is_protocol,
                        help='By default checks A, CNAME, NS info.')
    parser.add_argument('details', nargs='?',
                        help='Checks SOA, WHOIS, and default DNS records.')
    parser.add_argument('cdn', nargs='?', help='Only checks for CDN')
    parser.add_argument('ssl', nargs='?',
                        help='Checks SSL information for domain')
    parser.add_argument('--help', '-h', help='Prints out usage info/help', 
                        action='store_true')
    return parser


def main():
    args = arg_parser().parse_args()
    if args.help:
        print(usage())
    # Print help if no arguments are supplied.
    # Initializing our class
    dig = Digger(args.domain)
    record_type = ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT')
    # Get the SSL information
    ssl_info = ssl(args.domain)
    ssl_text_info = ssl_text(ssl_info)
    # ssl_detail_info = ssl_details(ssl_text_info, args.domain)
    domain = args.domain

    # whois = whois_formatter(whois_output)
    # Hacky way to get around using argparse for a menu.
    if len(argv) == 2:
        print(f'DNS Report for {args.domain}\n')
        default_records(dig, record_type)

    elif len(argv) == 3:
        if 'details' in argv[2]:
            print(f'DNS Report for {args.domain} \n')
            detailed_records(dig, record_type)

        elif 'cdn' in argv[2]:
            print(f'DNS Report for {args.domain} \n')
            print('-- A record(s) --')
            print(dig.stdout(record_type[0]))
            print('-- CNAME record(s) --')
            cdn_check(dig)

        elif 'ssl' in argv[2]:
            ssl_details(ssl_text_info, args.domain)

        elif 'whois' in argv[2]:
            print(f'WHOIS for {args.domain}\n')
            whois_raw = WhoisCheck(dig._domain)
            print(whois_formatter(whois_raw._whois_dict()))

    elif len(argv) == 4:
        if 'ssl' in argv[2]:
            if 'debug' in argv[3]:
                print(ssl_debug(args.domain))
        elif 'ssl' not in argv[2]:
            print(f"Not using 'debug' with 'ssl' argument")



if __name__ == '__main__':
    main()
