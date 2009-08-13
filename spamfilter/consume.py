import re, sys
import email
import base64
import quopri
from cStringIO import StringIO
from email.generator import Generator
from email.utils import parseaddr
from spamfilter.model.spam import Spam
from spamfilter.model.autowhitelist import AutoWhitelist
from spamfilter.model.greylist import createGreylistClass
from spamfilter.mixin import *

class SpamConsumer(ConfigMixin):
    def __init__(self, config):
        self.readConfig(config)

    def process(self):
        message = email.message_from_file(sys.stdin)
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.host = self.getConfigItem('spamfilter', 'host')
        try:
            self.processMessage(message)
            self.session.commit()
        except:
            self.session.rollback()
            raise

    def processMessage(self, message):
        if message.get_content_type() == 'message/rfc822':
            embedded = message.get_payload(0)
            if message['Content-Transfer-Encoding'] == 'base64':
                embedded = email.message_from_string(
                    base64.b64decode(embedded.get_payload()))
            elif message['Content-Transfer-Encoding'] == 'quoted-printable':
                embedded = email.message_from_string(
                    quopri.decodestring(embedded.get_payload()))
            
            self.saveSpam(embedded)
        elif 'attachment' in (message['Content-Disposition'] or ''):
            self.saveSpam(email.message_from_string(message.get_payload()))
        else:
            payload = message.get_payload()
            if isinstance(payload, list):
                for p in payload:
                    self.processMessage(p)

    def saveSpam(self, message):
        # Extract the attached message and save it in the spam table.
        mail_from = parseaddr(message['Return-Path'] or message['From'])[1]
        ips, helo = getReceivedIPsAndHelo(message, self.host)
        fp = StringIO()
        g = Generator(fp, mangle_from_=False)
        g.flatten(message)
        spam = Spam(mail_from=mail_from, ip_address=ips[0], helo=helo,
                    contents=fp.getvalue(), score=0)
        self.session.add(spam)

        # Remove the greylist entry.
        query = self.session.query(createGreylistClass())
        recipient = message.get_all('X-Original-To')[0]
        classc = '.'.join(ips[0].split('.')[:3])
        query = query.filter_by(rcpt_to=recipient, mail_from=mail_from,
                                ip_address=classc)
        greylist = query.first()
        if greylist:
            self.session.delete(greylist)

        # Update the auto-whitelist score.
        mail_from = parseaddr(message['From'] or message['Return-Path'])[1]
        query = self.session.query(AutoWhitelist)
        query = query.filter_by(email=mail_from)
        processed_classbs = {}
        for ip in ips:
            classb = '.'.join(ip.split('.')[:2])
            if classb in processed_classbs:
                continue

            processed_classbs[classb] = True
            record = query.filter_by(ip=classb).first()
            if record:
                record.totscore += record.count * 1000
            else:
                record = AutoWhitelist(username='GLOBAL', email=mail_from,
                                       ip=classb, count=1, totscore=1000)
                self.session.add(record)
