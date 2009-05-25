import re, sys
from email.parser import FeedParser
from cStringIO import StringIO
from email.generator import Generator
from email.utils import parseaddr
from spamfilter.model.spam import Spam
from spamfilter.model.auto_whitelist import AutoWhitelist
from spamfilter.model.greylist import createGreylistClass
from spamfilter.mixin import *

class SpamConsumer(ConfigMixin):
    def __init__(self, config):
        self.readConfig(config)

    def process(self):
        parser = FeedParser()
        for line in sys.stdin:
            parser.feed(line)

        message = parser.close()
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.host = self.getConfigItem('spamconsumer', 'host')
        try:
            self.processMessage(message)
            self.session.commit()
        except:
            self.session.rollback()
            raise

    def processMessage(self, message):
        if message.get_content_type() == 'message/rfc822':
            self.saveSpam(message.get_payload()[0])
        else:
            payload = message.get_payload()
            if isinstance(payload, list):
                for p in payload:
                    self.processMessage(p)

    def saveSpam(self, message):
        # Extract the attached message and save it in the spam table.
        mail_from = parseaddr(message['Return-Path'] or message['From'])[1]
        received = message.get_all('Received')
        from_re = re.compile(r'^from\s+(\S+)')
        ips = []
        found_helo = False
        for line in received:
            match = from_re.search(line)
            if match:
                if match.group(1) == self.host:
                    continue
                elif match.group(1) == 'localhost':
                    continue
                else:
                    if not found_helo:
                        helo = match.group(1)
                        found_helo = True

                    match = re.search(r'\[([\d\.]+)\]', line)
                    if match:
                        ips.append(match.group(1))

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
        for ip in ips:
            classb = '.'.join(ip.split('.')[:2])
            record = query.filter_by(ip=classb).first()
            if record:
                record.totscore += 1000
                record.count += 1
            else:
                record = AutoWhitelist(username='GLOBAL', email=mail_from,
                                       ip=classb, count=1, totscore=1000)
                self.session.add(record)
