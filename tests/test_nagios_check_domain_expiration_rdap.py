import importlib.util
import sys
import types
import unittest
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'src' / 'nagios_check_domain_expiration_rdap' / 'nagios_check_domain_expiration_rdap.py'


def load_module():
    fake_nagiosplugin = types.ModuleType('nagiosplugin')
    fake_nagiosplugin.Resource = object
    fake_nagiosplugin.Summary = object
    fake_nagiosplugin.Metric = lambda *args, **kwargs: (args, kwargs)
    fake_nagiosplugin.ScalarContext = lambda *args, **kwargs: (args, kwargs)
    fake_nagiosplugin.Check = lambda *args, **kwargs: types.SimpleNamespace(main=lambda verbose=0: None)
    fake_nagiosplugin.guarded = lambda func: func
    sys.modules['nagiosplugin'] = fake_nagiosplugin

    spec = importlib.util.spec_from_file_location('nagios_check_domain_expiration_rdap', str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload=None, status_code=200, url='https://example.test/', json_error=None):
        self.payload = payload
        self.status_code = status_code
        self.url = url
        self.json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError('HTTP {}'.format(self.status_code), response=self)

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, allow_redirects=True, headers=None, timeout=None):
        self.calls.append({
            'url': url,
            'allow_redirects': allow_redirects,
            'headers': headers,
            'timeout': timeout,
        })
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class RDAPTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def bootstrap(self):
        return {
            'services': [
                [['com'], ['https://rdap.example.com/']],
                [['ar'], ['https://rdap.nic.ar/']],
            ]
        }

    def test_discovers_authoritative_rdap_base_url_for_ar_domain(self):
        session = FakeSession([FakeResponse(self.bootstrap())])

        urls = self.module.discover_rdap_base_urls('zoeytextil.com.ar', session=session, timeout=7)

        self.assertEqual(['https://rdap.nic.ar/'], urls)
        self.assertEqual(self.module.IANA_DNS_BOOTSTRAP_URL, session.calls[0]['url'])
        self.assertEqual(7, session.calls[0]['timeout'])
        self.assertIn('check_expiration_rdap/', session.calls[0]['headers']['User-Agent'])
        self.assertIn('application/rdap+json', session.calls[0]['headers']['Accept'])

    def test_calculates_days_to_expiration_from_rdap_event(self):
        session = FakeSession([
            FakeResponse(self.bootstrap()),
            FakeResponse({'events': [{'eventAction': 'expiration', 'eventDate': '2026-07-20T00:00:00Z'}]}),
        ])

        days = self.module.rdap_days_to_expiration(
            'ZOEYTEXTIL.COM.AR.',
            session=session,
            today=self.module.date(2026, 7, 4),
        )

        self.assertEqual(16, days)
        self.assertEqual('https://rdap.nic.ar/domain/zoeytextil.com.ar', session.calls[1]['url'])

    def test_missing_expiration_event_is_unknown_not_zero_days(self):
        with self.assertRaisesRegex(self.module.RDAPLookupError, 'expiration event'):
            self.module.expiration_date_from_rdap({'events': [{'eventAction': 'registration'}]})

    def test_connection_error_includes_endpoint(self):
        session = FakeSession([
            FakeResponse(self.bootstrap()),
            requests.ConnectionError('reset by peer'),
        ])

        with self.assertRaisesRegex(self.module.RDAPLookupError, 'https://rdap.nic.ar/domain/zoeytextil.com.ar'):
            self.module.rdap_days_to_expiration('zoeytextil.com.ar', session=session)

    def test_http_error_is_reported_as_lookup_error(self):
        session = FakeSession([
            FakeResponse(self.bootstrap()),
            FakeResponse({'errorCode': 404}, status_code=404, url='https://rdap.example.com/domain/example.com'),
        ])

        with self.assertRaisesRegex(self.module.RDAPLookupError, 'HTTP error'):
            self.module.rdap_days_to_expiration('example.com', session=session)


if __name__ == '__main__':
    unittest.main()
