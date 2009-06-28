import os
import smtplib
import hashlib
import random
import time
import mx.DateTime
from mx.DateTime.ARPA import str as rfc822str
from sqlalchemy import select, text
import codecs
from email.header import decode_header

from spamfilter.mixin import ConfigMixin, createSession
from spamfilter.model.spam import Spam, SpamRecipient, spam_recipients_table
from spamfilter.model.virus import Virus, VirusRecipient, virus_recipients_table
from mako.template import Template

class MessageSummary(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

class ReportGenerator(ConfigMixin):
    def __init__(self, config):
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.template = Template(
            filename=os.path.join(os.path.dirname(__file__), 'report.txt'),
            input_encoding='utf-8', output_encoding='utf-8')
        
    def report(self):
        # Retrieve the addresses to which a quarantine message should be sent.
        connection = self.session.connection()
        query = select([spam_recipients_table.c.recipient])
        query = query.where(spam_recipients_table.c.delivery_id == None)
        query = query.group_by(spam_recipients_table.c.recipient)
        recipients = [x[0] for x in connection.execute(query)]

        # Add in any recipients who only received viruses.
        query = select([virus_recipients_table.c.recipient])
        query = query.where(virus_recipients_table.c.delivery_id == None)
        query = query.group_by(virus_recipients_table.c.recipient)
        virus_recipients = [x[0] for x in connection.execute(query)]
        for recipient in virus_recipients:
            if recipient not in recipients:
                recipients.append(recipient)

        # Send a quarantine report to each recipient. Each report is generated
        # and sent out within a single database transaction, and we make two
        # attempts per user to send the report before giving up.
        host = self.getConfigItem('report', 'host')
        random.seed()
        for recipient in recipients:
            attempt = 0
            while attempt < 2:
                try:
                    self.sendQuarantineReport(recipient, host)
                    self.session.commit()
                    break
                except Exception, exc:
                    self.session.rollback()
                    attempt += 1
                    if attempt == 2:
                        print "Unable to send report to %s: %s" % \
                              (recipient, exc)
                    time.sleep(5)

    def sendQuarantineReport(self, recipient, host):
        # Determine the real recipient.
        connection = self.session.connection()
        query = text(
            'select delivery from quarantine_recipients where :x ~ regexp')
        result = connection.execute(query, x=recipient).fetchone()
        actual_recipient = result[0] if result else recipient

        # Create the message summaries for this recipient's spam and viruses.
        query = self.session.query(SpamRecipient)
        query = query.filter_by(recipient=recipient, delivery_id=None)
        spam = createMessageSummaries([x.spam for x in query.all()],
                                      recipient)
        query = self.session.query(VirusRecipient)
        query = query.filter_by(recipient=recipient, delivery_id=None)
        viruses = createMessageSummaries([x.virus for x in query.all()],
                                         recipient)

        # Extract the domain name from the recipient and determine the name of
        # the mail server.
        domain = recipient[recipient.index('@') + 1:]
        query = text('select display from domain_names where domain = :x')
        result = connection.execute(query, x=domain).fetchone()
        server_name = result[0] if result else domain

        # Construct and send the report.
        cur_date = mx.DateTime.now()
        msg_text = self.template.render(
            domain=domain, host=host, server_name=server_name,
            recipient=recipient, rfcdate=rfc822str(cur_date),
            subject_date=cur_date.strftime("%m/%d/%Y %I:%M %p"), spam=spam,
            viruses=viruses)
        mailServer = smtplib.SMTP('localhost')
        sender = 'do_not_reply@%s' % domain
        mailServer.sendmail(sender, actual_recipient, msg_text,
                            ['BODY=8BITMIME'])
        mailServer.quit()

def createMessageSummaries(messages, recipient):
    # Order the messages by date, and then create a summary of each message.
    messages.sort(key=lambda x: x.created)
    return [MessageSummary(mail_from=x.mail_from, subject=translate(x.subject),
                           date=x.created.replace(microsecond=0),
                           delivery_id=createDeliveryId(x, recipient))
            for x in messages]

def createDeliveryId(message, recipient):
    digest = hashlib.md5()

    # The MAIL FROM header can be null, if the spam was impersonating a bounce
    # message.
    if message.mail_from:
        digest.update(message.mail_from)

    # The subject can be null in some incorrectly formatted Asian spam.
    if message.subject:
        digest.update(message.subject)

    digest.update(str(message.created))
    digest.update(str(random.random()))
    delivery_id = digest.hexdigest()
    for message_recipient in message.recipients:
        if message_recipient.recipient == recipient:
            message_recipient.delivery_id = delivery_id
            break

    return delivery_id

def translate(text):
    if text:
        try:
            chunks = decode_header(text)
            translated = []
            for chunk in chunks:
                if chunk[1]:
                    translated.append(codecs.getdecoder(chunk[1])(chunk[0])[0])
                else:
                    translated.append(unicode(chunk[0]))

            translated = u' '.join(translated)
            return codecs.getencoder('utf8')(translated)[0]
        except:
            return text
    else:
        return text
