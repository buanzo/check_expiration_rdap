#!/usr/bin/env python3
import argparse
import nagiosplugin
import requests
import json
from datetime import datetime
from pprint import pprint


__version__ = '0.1'


def rdap_days_to_expiration(domain):
    url = 'https://rdap-bootstrap.arin.net/bootstrap/domain/{}'.format(domain)
    response = requests.get(url, allow_redirects=True)
    jr = response.json()
    if 'events' in jr:
        for event in jr['events']:
            if event['eventAction'] == 'expiration':
                fecha = event['eventDate'].split('T')[0]
                today = datetime.now()
                delta = datetime.strptime(fecha, '%Y-%m-%d') - today
                return(delta.days)
    else:
        return(None)


class DaysToExpiration(nagiosplugin.Resource):
    def __init__(self, domain):
        self.domain = domain

    def probe(self):
        days_to_expiration = rdap_days_to_expiration(self.domain)
        # FIX: use nagiosplugin.state.Unknown in LoadSummary?
        if days_to_expiration is None:
            days_to_expiration = 0
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
