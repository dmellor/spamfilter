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
import traceback

from spamfilter.mixin import ConfigMixin, create_session
from spamfilter.model.spam import SpamRecipient, spam_recipients_table
from spamfilter.model.virus import VirusRecipient, virus_recipients_table
from mako.template import Template


class MessageSummary(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


class ReportGenerator(ConfigMixin):
    def __init__(self, config):
        self.read_config(config)
        self.session = create_session(self.get_config_item('database', 'dburi'))
        self.template = Template(
            filename=os.path.join(os.path.dirname(__file__), 'report.txt'),
            input_encoding='utf-8', output_encoding='utf-8')

    # noinspection PyComparisonWithNone
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
        host = self.get_config_item('report', 'host')
        random.seed()
        for recipient in recipients:
            attempt = 0
            while attempt < 2:
                try:
                    self.send_quarantine_report(recipient, host)
                    self.session.commit()
                    break
                except Exception, exc:
                    self.session.rollback()
                    attempt += 1
                    if attempt == 2:
                        print "Unable to send report to %s: %s\n%s" % \
                              (recipient, exc, traceback.format_exc())
                    time.sleep(5)

    def send_quarantine_report(self, recipient, host):
        # Determine the real recipient.
        connection = self.session.connection()
        query = text(
            'select delivery from quarantine_recipients where :x ~ regexp')
        result = connection.execute(query, x=recipient).fetchone()
        actual_recipient = result[0] if result else recipient

        # Create the message summaries for this recipient's spam and viruses.
        query = self.session.query(SpamRecipient)
        query = query.filter_by(recipient=recipient, delivery_id=None)
        spam = create_message_summaries([x.spam for x in query.all()],
                                        recipient)
        query = self.session.query(VirusRecipient)
        query = query.filter_by(recipient=recipient, delivery_id=None)
        viruses = create_message_summaries([x.virus for x in query.all()],
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
        mail_server = smtplib.SMTP('localhost')
        sender = 'do_not_reply@%s' % domain
        mail_server.sendmail(sender, actual_recipient, msg_text,
                             ['BODY=8BITMIME'])
        mail_server.quit()


def create_message_summaries(messages, recipient):
    # Order the messages by date, and then create a summary of each message.
    messages.sort(key=lambda msg: msg.created)
    return [MessageSummary(bounce=translate(x.bounce),
                           subject=translate(x.subject),
                           date=x.created.replace(microsecond=0),
                           delivery_id=create_delivery_id(x, recipient))
            for x in messages]


def create_delivery_id(message, recipient):
    digest = hashlib.md5()

    # The MAIL FROM header can be null, if the spam was impersonating a bounce
    # message.
    if message.bounce:
        digest.update(message.bounce)

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


# This function tries to convert the text to Unicode. If that fails, then an
# ascii-encoded string will be returned.
def translate(txt):
    txt = _translate(txt)

    # Some email headers are incorrectly encoded. If the text was not encoded
    # according to RFC 2047, then we attempt to decode it to Unicode assuming
    # that the encoding is utf8. If that fails then we convert the text to
    # ascii encoding by deleting all non-ascii characters from the text.
    if not isinstance(txt, unicode):
        try:
            txt = txt.decode('utf8')
        except:
            txt = ''.join([x for x in txt if ord(x) < 128])

    return txt


# Transform the text according to RFC 2047.
def _translate(txt):
    if txt:
        try:
            chunks = decode_header(txt)
            translated = []
            for chunk in chunks:
                if chunk[1]:
                    translated.append(codecs.getdecoder(chunk[1])(chunk[0])[0])
                else:
                    translated.append(unicode(chunk[0]))

            return u''.join(translated)
        except:
            return txt
    else:
        # If the text was None, it is converted to an empty string in order to
        # prevent 'NoneType' object is not iterable when the return value of
        # this function is treated as a string.
        return '' if txt is None else txt
