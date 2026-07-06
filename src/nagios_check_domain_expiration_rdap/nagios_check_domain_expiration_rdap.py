#!/usr/bin/env python3
import argparse
import re
import nagiosplugin
import requests
import subprocess
from collections import namedtuple
from datetime import date, datetime
from urllib.parse import quote


__version__ = '0.2'

IANA_DNS_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
NIC_AR_WHOIS_HOST = 'whois.nic.ar'
DEFAULT_TIMEOUT = 15
USER_AGENT = 'check_expiration_rdap/{} (+https://github.com/buanzo/check_expiration_rdap)'.format(__version__)
ACCEPT_HEADER = 'application/rdap+json, application/json'
EXPIRATION_EVENT_ACTIONS = set(['expiration', 'registration expiration'])
NIC_AR_WHOIS_EXPIRE_RE = re.compile(
    r'^\s*expire:\s*(\d{4}-\d{2}-\d{2})(?:\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\s*$',
    re.IGNORECASE | re.MULTILINE)
ExpirationLookup = namedtuple('ExpirationLookup', ['expires', 'source', 'rdap_error'])


class RDAPLookupError(Exception):
    pass


def normalize_domain(domain):
    normalized = domain.strip().strip('.').lower()
    labels = normalized.split('.')
    if len(labels) < 2 or any(not label for label in labels):
        raise RDAPLookupError('invalid domain name: {}'.format(domain))
    try:
        return '.'.join(label.encode('idna').decode('ascii') for label in labels)
    except UnicodeError as exc:
        raise RDAPLookupError('invalid IDNA domain name {}: {}'.format(domain, exc))


def request_json(url, session=None, timeout=DEFAULT_TIMEOUT):
    session = session or requests.Session()
    headers = {
        'Accept': ACCEPT_HEADER,
        'User-Agent': USER_AGENT,
    }
    try:
        response = session.get(url, allow_redirects=True, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise RDAPLookupError('RDAP request failed for {}: {}'.format(url, exc))

    response_url = getattr(response, 'url', None) or url
    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RDAPLookupError('RDAP HTTP error for {}: {}'.format(response_url, exc))

    try:
        return response.json()
    except ValueError as exc:
        raise RDAPLookupError('RDAP invalid JSON from {}: {}'.format(response_url, exc))


def discover_rdap_base_urls(domain, session=None, timeout=DEFAULT_TIMEOUT):
    bootstrap = request_json(IANA_DNS_BOOTSTRAP_URL, session=session, timeout=timeout)
    services = bootstrap.get('services', [])
    matches = []
    for service in services:
        if len(service) != 2:
            continue
        suffixes, urls = service
        for suffix in suffixes:
            suffix = suffix.strip('.').lower()
            if domain == suffix or domain.endswith('.' + suffix):
                matches.append((suffix.count('.') + 1, urls))
    if not matches:
        raise RDAPLookupError('no RDAP bootstrap service found for {}'.format(domain))
    matches.sort(reverse=True)
    return matches[0][1]


def rdap_domain_url(base_url, domain):
    return '{}/domain/{}'.format(base_url.rstrip('/'), quote(domain, safe=''))


def fetch_domain_rdap(domain, session=None, timeout=DEFAULT_TIMEOUT):
    session = session or requests.Session()
    base_urls = discover_rdap_base_urls(domain, session=session, timeout=timeout)
    errors = []
    for base_url in base_urls:
        url = rdap_domain_url(base_url, domain)
        try:
            return request_json(url, session=session, timeout=timeout)
        except RDAPLookupError as exc:
            errors.append(str(exc))
    raise RDAPLookupError('all RDAP endpoints failed for {}: {}'.format(domain, '; '.join(errors)))


def expiration_date_from_rdap(payload):
    for event in payload.get('events', []):
        action = event.get('eventAction', '').lower()
        if action in EXPIRATION_EVENT_ACTIONS or 'expiration' in action:
            event_date = event.get('eventDate', '').split('T')[0]
            try:
                return datetime.strptime(event_date, '%Y-%m-%d').date()
            except ValueError:
                raise RDAPLookupError('invalid RDAP expiration date: {}'.format(event.get('eventDate')))
    raise RDAPLookupError('RDAP response did not include an expiration event')


def is_nic_ar_domain(domain):
    return domain == 'ar' or domain.endswith('.ar')


def decode_whois_output(output):
    if isinstance(output, bytes):
        return output.decode('utf-8', 'replace')
    return output


def query_nic_ar_whois(domain, timeout=DEFAULT_TIMEOUT):
    try:
        output = subprocess.check_output(
            ['whois', '-h', NIC_AR_WHOIS_HOST, domain],
            stderr=subprocess.STDOUT,
            timeout=timeout)
    except FileNotFoundError as exc:
        raise RDAPLookupError('WHOIS command not found: {}'.format(exc))
    except subprocess.TimeoutExpired:
        raise RDAPLookupError('WHOIS request timed out for {} via {}'.format(domain, NIC_AR_WHOIS_HOST))
    except subprocess.CalledProcessError as exc:
        output = decode_whois_output(exc.output or b'').strip().replace('\n', '; ')
        raise RDAPLookupError('WHOIS request failed for {} via {}: exit {} {}'.format(
            domain, NIC_AR_WHOIS_HOST, exc.returncode, output))
    return decode_whois_output(output)


def expiration_date_from_nic_ar_whois(whois_output):
    match = NIC_AR_WHOIS_EXPIRE_RE.search(whois_output)
    if not match:
        raise RDAPLookupError('NIC.ar WHOIS response did not include an expire field')
    try:
        return datetime.strptime(match.group(1), '%Y-%m-%d').date()
    except ValueError:
        raise RDAPLookupError('invalid NIC.ar WHOIS expiration date: {}'.format(match.group(1)))


def nic_ar_whois_expiration_date(domain, timeout=DEFAULT_TIMEOUT):
    return expiration_date_from_nic_ar_whois(query_nic_ar_whois(domain, timeout=timeout))


def domain_expiration_lookup(domain, session=None, timeout=DEFAULT_TIMEOUT, whois_lookup=None):
    domain = normalize_domain(domain)
    try:
        payload = fetch_domain_rdap(domain, session=session, timeout=timeout)
        return ExpirationLookup(expiration_date_from_rdap(payload), 'RDAP', None)
    except RDAPLookupError as rdap_error:
        if not is_nic_ar_domain(domain):
            raise
        whois_lookup = whois_lookup or nic_ar_whois_expiration_date
        try:
            expires = whois_lookup(domain, timeout=timeout)
        except RDAPLookupError as whois_error:
            raise RDAPLookupError('RDAP failed for {}: {}; WHOIS fallback failed via {}: {}'.format(
                domain, rdap_error, NIC_AR_WHOIS_HOST, whois_error))
        return ExpirationLookup(expires, 'WHOIS {}'.format(NIC_AR_WHOIS_HOST), str(rdap_error))


def domain_days_to_expiration(domain, session=None, timeout=DEFAULT_TIMEOUT, today=None, whois_lookup=None):
    lookup = domain_expiration_lookup(domain, session=session, timeout=timeout, whois_lookup=whois_lookup)
    today = today or date.today()
    return (lookup.expires - today).days


def rdap_days_to_expiration(domain, session=None, timeout=DEFAULT_TIMEOUT, today=None, whois_lookup=None):
    return domain_days_to_expiration(
        domain,
        session=session,
        timeout=timeout,
        today=today,
        whois_lookup=whois_lookup)


class DaysToExpiration(nagiosplugin.Resource):
    def __init__(self, domain):
        self.domain = domain
        self.source = None
        self.rdap_error = None

    def probe(self):
        lookup = domain_expiration_lookup(self.domain)
        today = date.today()
        days_to_expiration = (lookup.expires - today).days
        self.source = lookup.source
        self.rdap_error = lookup.rdap_error
        return [nagiosplugin.Metric('daystoexpiration',
                                    days_to_expiration,
                                    context='daystoexpiration')]


class LoadSummary(nagiosplugin.Summary):
    def __init__(self, domain):
        self.domain = domain

    def ok(self, results):
        return self._format_with_source(results[0])

    def problem(self, results):
        return self._format_with_source(results.first_significant)

    def _format_with_source(self, result):
        message = '{}'.format(result)
        source = getattr(result.resource, 'source', None)
        if source and source != 'RDAP':
            message = '{} via {}'.format(message, source)
        return message


@nagiosplugin.guarded
def main():
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-w', '--warning', metavar='RANGE', default='15:30',
                      help='warning expiration RANGE days. Default=15:30')
    argp.add_argument('-c', '--critical', metavar='RANGE', default='0:15',
                      help='critical expiration RANGE days. Default=0:15')
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='be more verbose')
    argp.add_argument('domain')
    args = argp.parse_args()
    wrange = '@{}'.format(args.warning)
    crange = '@{}'.format(args.critical)
    fmetric = '{value} days until domain expires'
    # FIX: add 'isvaliddomainname' test
    check = nagiosplugin.Check(DaysToExpiration(args.domain),
                               nagiosplugin.ScalarContext('daystoexpiration',
                                                          warning=wrange,
                                                          critical=crange,
                                                          fmt_metric=fmetric),
                               LoadSummary(args.domain))
    check.main(verbose=args.verbose)


if __name__ == '__main__':
    main()
