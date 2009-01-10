#!/bin/sh

python2.5 migrate.py

echo 'copy domain_names from stdin;'
psql -h granite -c 'copy domain_names to stdout' spamassassin
echo '\.'

echo 'copy spam(mail_from, ip_address, helo, contents, score, tests, created) from stdin;'
psql -h granite -c 'copy spam(mail_from, ip_address, helo, contents, score, tests, created) to stdout' spamassassin
echo '\.'
