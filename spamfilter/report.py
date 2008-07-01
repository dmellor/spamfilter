import string
import smtplib
import md5
import random
import time
import sys
import mx.DateTime
from mx.DateTime.ARPA import str as rfc822str
from sqlalchemy import select, text

from spamfilter.mixin import ConfigMixin, SessionMixin
from spamfilter.model.spam import Spam, SpamRecipient, spam_recipients_table

HEADERS = '''From: <do_not_reply@${domain}>
To: $recipient
Date: $rfcdate
Subject: Spam quarantine summary $subject_date
Content-Type: text/html; charset=iso-8859-1
Content-Transfer-Encoding: 8bit

'''

PREAMBLE = '''<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<html>
<body bgcolor="#FFFFFF">
<table width="100%" cellspacing="0" cellpadding="1" border="0">
<tr><td>
<font face="Arial, Helvetica, sans-serif" size="-1">
$recipient
<p>
<B>Spam Email Blocked by the $server_name Mail Server</B><P>
Clicking on the "deliver" links below will cause the corresponding
quarantined message to be delivered to your mailbox.
<B>Spam is automatically purged from your quarantine queue after 14 days,
freeing you from having to do it manually.</B><p>
</font></td></tr></table>
<br><br>
<table width="100%" cellspacing="0" cellpadding="1" border="0">
<tr bgcolor="#FFFFFF">
<td width="30%">
<font face="Arial, Helvetica, sans-serif" size="-1" color="#666666">
<b>Junk Messages</b>
</font>
</td>
<td width="40%">
<font face="Arial, Helvetica, sans-serif" size="-2">
$num_messages
</font>
</td>
<td width="20%">
&nbsp;</td>
<td>&nbsp;</td></tr>
<tr bgcolor="#666666">
<td>
<font face="Arial, Helvetica, sans-serif" size="-1" color="#FFFFFF">
<b>From</b>
</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1" color="#FFFFFF">
<b>Subject</b>
</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1" color="#FFFFFF">
<b>Date</b></font></td><td>&nbsp;</td></tr>
'''

ROW_TEXT = '''<tr bgcolor="${colour}">
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">$mail_from</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">$subject</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">$msg_date</font>
</td>
<td><font face="Arial, Helvetica, sans-serif" size="-1" color="#FFFFFF">
<a href="http://${host}/cgi-bin/deliver/${delivery_id}">Deliver</a>
</font></td>
</tr>
'''

SUFFIX = '''</table>
<br><br>
</font>
</body>
</html>
'''

class ReportGenerator(ConfigMixin, SessionMixin):
    def __init__(self, config_file):
        self.readConfig(config_file)
        self.createSession(self.getConfigItem('database', 'dburi'))
        
    def report(self):
        # Retrieve the addresses to which a quarantine message should be sent.
        connection = self.session.connection()
        query = select([spam_recipients_table.c.recipient])
        query = query.where(spam_recipients_table.c.delivery_id == None)
        query = query.group_by(spam_recipients_table.c.recipient)
        recipients = [x[0] for x in connection.execute(query)]

        # Send a quarantine report to each recipient. Each report is generated
        # and sent out within a single database transaction, and we make five
        # attempts per user to send the report before giving up.
        host = self.getConfigItem('report', 'host')
        random.seed()
        for recipient in recipients:
            attempt = 0
            while attempt < 5:
                try:
                    self.sendQuarantineReport(recipient, host)
                    self.session.commit()
                    break
                except Exception, exc:
                    self.session.rollback()
                    self.session.clear()
                    attempt += 1
                    if attempt == 5:
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

        # Retrieve the spam recipient records for this recipient.
        query = self.session.query(SpamRecipient)
        query = query.filter_by(recipient=actual_recipient, delivery_id=None)
        records = query.all()

        # Retrieve the spam, sorting it by creation date.
        spam = [x.spam.one() for x in records]
        spam.sort(key=lambda x: x.created)

        # Extract the domain name from the recipient and determine the name of
        # the mail server.
        domain = recipient[recipient.index('@') + 1:]
        query = text('select display from domain_names where domain = :x')
        result = connection.execute(query, x=domain).fetchone()
        server_name = result[0] if result else domain

        # Construct the message.
        headers_template = string.Template(HEADERS)
        cur_date = mx.DateTime.now()
        msg_text = [headers_template.substitute(
            recipient=recipient,
            rfcdate=rfc822str(cur_date),
            domain=domain,
            subject_date=cur_date.strftime("%m/%d/%Y %I:%M %p"))]
        preamble_template = string.Template(PREAMBLE)
        if len(spam) == 1:
            num_messages = '1 Message'
        else:
            num_messages = '%s Messages' % len(spam)

        msg_text.append(
            preamble_template.substitute(recipient=recipient,
                                         num_messages=num_messages,
                                         server_name=server_name))
        row_template = string.Template(ROW_TEXT)
        i = 0
        for msg in spam:
            if i & 1 == 0:
                colour = "#FFFFFF"
            else:
                colour = "#EEEEEE"

            i += 1
            msg_date = msg.created.replace(microsecond=0)
            digest = md5.new()

            # The MAIL FROM header can be null, if the spam was impersonating a
            # bounce message.
            if msg.mail_from:
                digest.update(msg.mail_from)

            # The subject can be null in some incorrectly formatted Asian spam.
            if msg.subject:
                digest.update(msg.subject)

            digest.update(str(msg_date))
            digest.update(str(random.random()))
            delivery_id = digest.hexdigest()
            msg_text.append(
                row_template.substitute(
                    mail_from=msg.mail_from, subject=msg.subject,
                    msg_date=msg_date, delivery_id=delivery_id, colour=colour,
                    host=host))
            for spam_recipient in msg.recipients:
                if spam_recipient.recipient == recipient:
                    spam_recipient.delivery_id = delivery_id
                    break

        msg_text.append(SUFFIX)

        # Deliver the message.
        mailServer = smtplib.SMTP('localhost')
        sender = 'do_not_reply@%s' % domain
        mailServer.sendmail(sender, actual_recipient, ''.join(msg_text),
                            ['BODY=8BITMIME'])
        mailServer.quit()
