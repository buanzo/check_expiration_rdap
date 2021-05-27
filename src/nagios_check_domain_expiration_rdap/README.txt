Hi, thanks for testing this plugin.

OK unzip the nagios_check_domain_expiration_rdap.zip file somewhere, chdir there.
there should be a *.py file and requirements.txt.
now install python3 dependencies:

pip3 install requests nagiosplugin

if you don't have pip3, you might need to run pip. BUT make sure Python 3 is installed. I tested with Python>= 3.5.

Once the required modules are installed (you can also feed requirements.txt to pip3), test it out:

python3 nagios_check_domain_expiration_rdap.py example.net

Feel free to replace example.net with one of your domains. :)

If python3 is not in your path, make sure it is installed.  python without
the version number might be v2 or v3 in your system, YMMV.

I suggest you rename the .py file to something more comfortable whilst you copy it to /usr/local/bin (or whatever!).

cp nagios_check_domain_expiration_rdap.py /usr/local/bin/check_rdap_expire

Take note of that path. Head into your nagios configuration, add this command:

define command{
        command_name    check_rdap_expire
        command_line    /usr/local/bin/check_rdap_expire $ARG1$
}


And add a service block to one of your hosts:

define service{
 use                 generic-service
 host_name           localhost
 service_description EXPIRATION example.net
 check_command       check_rdap_expire!example.net
 check_interval      1440  ; Server are checked every 1 day when in OK state
 retry_interval      180   ; Server checked every 3 hours if in problem state
 max_check_attempts  3     ; Server checked 3 times to determine if its Up or Down state
}

Reload your nagios config, and enjoy!

File bugs here: https://github.com/buanzo/check_expiration_rdap/issues

Cheers,
Buanzo
