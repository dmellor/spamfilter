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
from spamfilter.extract import EmailExtractor

class SpamConsumer(EmailExtractor, ConfigMixin):
    def __init__(self, config):
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.host = self.getConfigItem('spamfilter', 'host')

    def actOnMessage(self, message):
        try:
            self.saveSpam(message)
            self.session.commit()
        except:
            self.session.rollback()
            raise

    def saveSpam(self, message):
        # Extract the attached message and save it in the spam table.
        bounce = parseaddr(message['Return-Path'] or message['From'])[1]
        mail_from = bounce.lower() if bounce else None
        ips, helo = getReceivedIPsAndHelo(message, self.host)
        fp = StringIO()
        g = Generator(fp, mangle_from_=False)
        g.flatten(message)
        spam = Spam(bounce=bounce, ip_address=ips[0], helo=helo,
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
        mail_from = parseaddr(
            message['From'] or message['Return-Path'])[1].lower()
        query = self.session.query(AutoWhitelist)
        query = query.filter_by(email=mail_from)
        processed_classbs = {}
        for ip in ips:
            classb = '.'.join(ip.split('.')[:2])
            if classb in processed_classbs:
                continue

            processed_classbs[classb] = True
            for record in query.filter_by(ip=classb).all():
                record.totscore += record.count * 1000
