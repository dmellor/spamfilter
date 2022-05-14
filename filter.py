import sys
import re
import email
import quopri
import base64
import smtplib
import logging
import traceback
from spamfilter.mixin import *
from spamfilter.model.filtered import Filtered


class Filter(ConfigMixin):
    def __init__(self):
        self.read_config('config.ini')
        self.session = create_session(
            self.get_config_item('database', 'dburi'), serializable=False)

    def filter_message(self, recipient, filter_file):
        original_message = sys.stdin.read()
        sys.stdin.close()

        # Do not filter spam summary messages
        nofilter = self.get_config_item('filter', 'nofilter', None)
        if nofilter:
            prefix = 'From ' + nofilter
            if original_message.startswith(prefix):
                deliver_message(recipient, original_message)
                return

        message = email.message_from_string(original_message)
        body = extract_text_content(message)

        accepted = True
        with open(filter_file, 'r') as f:
            while True:
                line = f.readline()
                if not line:
                    break

                line = line.rstrip()
                regexp = re.compile(line, re.I | re.M)
                if regexp.search(body):
                    accepted = False
                    break

        if accepted:
            deliver_message(recipient, original_message)
        else:
            self.record_message(recipient, original_message)

    def record_message(self, recipient, message):
        try:
            filtered_message = Filtered(recipient=recipient, contents=message)
            self.session.add(filtered_message)
            self.session.commit()
        except Exception, exc:
            self.session.rollback()
            err_status = re.sub(r'\r?\n', ' ', str(exc))
            logging.info('filter failed: %s', err_status)
            logging.info(traceback.format_exc())


def extract_text_content(message):
    payload = message.get_payload()
    content_type = message.get_content_type()
    charset = message.get_param('charset')
    body = None
    if not isinstance(payload, list):
        if content_type in ('text/plain', 'text/html'):
            body = payload
            encoding = message.get('Content-Transfer-Encoding', '').lower()
            if encoding == 'quoted-printable':
                body = quopri.decodestring(body)
            elif encoding == 'base64':
                body = base64.b64decode(body)

            try:
                body = body.decode(charset).encode('utf8')
            except UnicodeDecodeError:
                # If message was badly encoded then process without decoding.
                pass
    else:
        for msg in payload:
            body = extract_text_content(msg)
            if body:
                break

    return body


def deliver_message(recipient, message):
    server = smtplib.SMTP('localhost')
    server.sendmail('root@localhost', recipient, message, ['BODY=8BITMIME'])
    server.quit()


if __name__ == '__main__':
    Filter().filter_message(sys.argv[1], sys.argv[2])
