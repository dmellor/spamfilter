import sys
import email
import re
import random
import smtplib
import logging
import traceback
from spamfilter.mixin import *
from cStringIO import StringIO
from email.generator import Generator


class Forward(ConfigMixin):
    def __init__(self):
        self.read_config('config.ini')
        self.forward_db = self.get_config_item('forward', 'forward_db')
        self.mailing_list_db = self.get_config_item('forward',
                                                    'mailing_list_db')
        self.domain = self.get_config_item('spamfilter', 'domain')

    def forward_message(self, recipient):
        message = sys.stdin.read()
        sys.stdin.close()
        message = email.message_from_string(message)
        if query_postfix_db(self.mailing_list_db, recipient):
            message['Reply-To'] = recipient

        from_header = message['From']
        match = re.search(r'<([^>]+)>', from_header)
        address = match.group(1).lower()
        srs_address = generate_srs_address(address, self.domain)
        forwards = get_postfix_db_value(self.forward_db, recipient)
        forwards = [x.strip() for x in forwards.split(',')]
        server = smtplib.SMTP('localhost')
        fp = StringIO()
        g = Generator(fp, mangle_from_=False)
        g.flatten(message)
        server.sendmail(srs_address, forwards, fp.getvalue(),
                        ['BODY=8BITMIME'])


if __name__ == '__main__':
    try:
        Forward().forward_message(sys.argv[1])
    except Exception, exc:
        err_status = re.sub(r'\r?\n', ' ', str(exc))
        logging.info('filter failed: %s', err_status)
        logging.info(traceback.format_exc())
