# rdap-nagios

A nagios plugin to check domain name expiration date using an RDAP backend.

## Documentation

This plugin discovers the authoritative RDAP endpoint for a domain through
IANA's DNS RDAP bootstrap data, then reads the domain RDAP object and extracts
its expiration event.

It is intended to be a general RDAP expiration check. It was developed with a
specific operational need for reliable `.ar` expiration monitoring, so `.ar`
behavior should stay covered by tests when changing endpoint discovery or
failure handling.

## Installing

Install Python 3 dependencies:

```sh
pip3 install -r src/nagios_check_domain_expiration_rdap/requirements.txt
```

Copy the plugin to the Nagios host:

```sh
cp src/nagios_check_domain_expiration_rdap/nagios_check_domain_expiration_rdap.py /usr/local/bin/check_rdap_expire
chmod 755 /usr/local/bin/check_rdap_expire
```

If the target host uses a specific Python interpreter, keep the Nagios command
pointed at that interpreter.

## Testing

```sh
python3 src/nagios_check_domain_expiration_rdap/nagios_check_domain_expiration_rdap.py example.net
python3 -m unittest discover -s tests
```

Transport, HTTP, JSON, or missing-expiration failures return Nagios UNKNOWN
with the endpoint in the error text. They are not treated as zero days to
expiration.

## Configure as Nagios Plugin

```cfg
define command{
        command_name    check_rdap_expire
        command_line    /usr/local/bin/check_rdap_expire $ARG1$
}
```

## Add a service check

```cfg
define service{
 use                 generic-service
 host_name           localhost
 service_description EXPIRATION example.net
 check_command       check_rdap_expire!example.net
 check_interval      1440
 retry_interval      180
 max_check_attempts  3
}
```
