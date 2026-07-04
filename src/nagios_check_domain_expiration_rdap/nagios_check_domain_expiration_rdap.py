#!/usr/bin/env python3
import argparse
import nagiosplugin
import requests
from datetime import date, datetime
from urllib.parse import quote


__version__ = '0.2'

IANA_DNS_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
DEFAULT_TIMEOUT = 15
USER_AGENT = 'check_expiration_rdap/{} (+https://github.com/buanzo/check_expiration_rdap)'.format(__version__)
ACCEPT_HEADER = 'application/rdap+json, application/json'
EXPIRATION_EVENT_ACTIONS = set(['expiration', 'registration expiration'])


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


def rdap_days_to_expiration(domain, session=None, timeout=DEFAULT_TIMEOUT, today=None):
    domain = normalize_domain(domain)
    payload = fetch_domain_rdap(domain, session=session, timeout=timeout)
    expires = expiration_date_from_rdap(payload)
    today = today or date.today()
    return (expires - today).days


class DaysToExpiration(nagiosplugin.Resource):
    def __init__(self, domain):
        self.domain = domain

    def probe(self):
        days_to_expiration = rdap_days_to_expiration(self.domain)
        return [nagiosplugin.Metric('daystoexpiration',
                                    days_to_expiration,
                                    context='daystoexpiration')]


class LoadSummary(nagiosplugin.Summary):
    def __init__(self, domain):
        self.domain = domain
    pass


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
