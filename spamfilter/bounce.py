import sys, re
import email
from email.mime.text import MIMEText
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.generator import Generator
from email.utils import parseaddr
from cStringIO import StringIO
import mx.DateTime
from mx.DateTime.ARPA import str as rfc822str
import smtplib
from spamfilter.extract import EmailExtractor

BOUNCE_MESSAGE = """This is the mail system at host quartz.whistlingcat.com.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients. It's attached below.

For further assistance, please send mail to <postmaster>

If you do so, please include this problem report. You can
delete your own text from the attached returned message.

                   The mail system

<%(recipient)s>: 550 5.2.1 Address unknown
"""

STATUS_MESSAGE = """Reporting-MTA: dns; quartz.whistlingcat.com
X-Postfix-Queue-ID: %(queue_id)s
X-Postfix-Sender: rfc822; %(sender)s
Arrival-Date: %(date)s

Final-Recipient: rfc822; %(recipient)s
Original-Recipient: rfc822;%(recipient)s
Action: failed
Status: 5.2.1
Diagnostic-Code: x-unix; 550 5.2.1 Address unknown

"""

def generate_bounce(spam, sender):
    del spam['Delivered-To']
    del spam['X-Original-To']
    params = dict(sender=sender)
    received = spam.get_all('Received')[0]
    match = re.search(r'for <([^>]+)>;\s+(.*)$', received, re.MULTILINE)
    params['recipient'] = match.group(1)
    params['date'] = match.group(2)
    match = re.search(r'\bwith \w+ id ([0-9A-F]+)', received)
    params['queue_id'] = match.group(1)

    # Create MIME objects for the message parts.
    notification = MIMEText(BOUNCE_MESSAGE % params)
    notification['Content-Description'] = 'Notification'
    report = MIMEMessage(email.message_from_string(STATUS_MESSAGE % params),
                         'delivery-status')
    report['Content-Description'] = 'Delivery report'
    contents = MIMEMessage(spam)
    contents['Content-Description'] = 'Undelivered Message'
    _params={'report-type': 'delivery-status'}
    message = MIMEMultipart('report', **_params)
    message.attach(notification)
    message.attach(report)
    message.attach(contents)
    message['From'] = \
        'MAILER-DAEMON@quartz.whistlingcat.com (Mail Delivery System)'
    message['To'] = sender
    message['Subject'] = 'Undelivered Mail Returned to Sender'
    message['Date'] = rfc822str(mx.DateTime.now())
    message['Auto-Submitted'] = 'auto-replied'
    fp = StringIO()
    g = Generator(fp, mangle_from_=False)
    g.flatten(message)
    return fp.getvalue()

def bounce_file():
    bouncer = FileBouncer()
    if len(sys.argv) == 1 or sys.argv[1] == '-':
        bouncer.process(sys.stdin)
    else:
        fp = open(sys.argv[1])
        bouncer.process(fp)

def bounce_db():
    config = sys.argv[1]
    spam_id = int(sys.argv[2])
    bouncer = DbBouncer(config)
    bouncer.bounceFromId(spam_id)

def bounce(spam, sender=None):
    if not sender:
        sender = parseaddr(spam['Return-Path'])[1]

    del spam['Return-Path']
    bounce_text = generate_bounce(spam, sender)
    smtp = smtplib.SMTP()
    smtp.connect()
    smtp.sendmail('', sender, bounce_text)
    smtp.quit()

class FileBouncer(EmailExtractor):
    def actOnMessage(self, message):
        bounce(message)

from spamfilter.mixin import *
class DbBouncer(ConfigMixin):
    def __init__(self, config):
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))

    def bounceFromId(self, spam_id):
        from spamfilter.model.spam import Spam
        spam = self.session.query(Spam).get(spam_id)
        spam_message = email.message_from_string(spam.contents)
        bounce(spam_message, spam.bounce)
        self.session.commit()
