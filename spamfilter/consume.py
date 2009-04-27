import re, sys, logging
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
                    ips.append(match.group(1))

        fp = StringIO()
        g = Generator(fp, mangle_from_=False)
        g.flatten(message)
        spam = Spam(mail_from=mail_from, ip_address=ips[0], helo=helo,
                    contents=fp.getvalue(), score=0, tests='REPORT')
        self.session.save(spam)

        # Remove the greylist entry.
        klass = createGreylistClass()
        query = self.session.query(klass)
        recipient = message['X-Original-To']
        classc = '.'.join(ips[0].split('.')[0:3])
        query = query.filter_by(rcpt_to=recipient, mail_from=mail_from,
                                ip_address=classc)
        greylist = query.first()
        if greylist:
            self.session.delete(greylist)

        # Update the auto-whitelist score.
        query = self.session.query(AutoWhitelist)
        query = query.filter_by(email=mail_from)
        for ip in ips:
            classb = '.'.join(ip.split('.')[0:2])
            record = query.filter_by(ip=classb).first()
            if record:
                record.totscore += 1000
