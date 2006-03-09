#!/usr/bin/python2.4
# $Id$

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_SERIALIZABLE
import string
import smtplib
import md5
import random
import time
import mx.DateTime
from mx.DateTime.ARPA import str as rfc822str

headers = """From: <do_not_reply@${domain}>
To: $recipient
Date: $rfcdate
Subject: Spam quarantine summary $subjectDate
Content-Type: text/html; charset=iso-8859-1
Content-Transfer-Encoding: 8bit

"""

preamble = """<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<html>
<body bgcolor="#FFFFFF">
<table width="100%" cellspacing="0" cellpadding="1" border="0">
<tr><td>
<font face="Arial, Helvetica, sans-serif" size="-1">
$recipient
<p>
<B>Spam Email Blocked by the $serverName Mail Server</B><P>
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
$numMessages
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
"""

rowText = """<tr bgcolor="${colour}">
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">
$mailFrom
</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">
$subject
</font>
</td>
<td>
<font face="Arial, Helvetica, sans-serif" size="-1">
$msgDate
</font>
</td>
<td><font face="Arial, Helvetica, sans-serif" size="-1" color="#FFFFFF">
<a href="http://www.whistlingcat.com/cgi-bin/deliver/${deliveryId}">Deliver</a>
</font></td>
</tr>
"""

suffix = """</table>
<br><br>
</font>
</body>
</html>
"""

def main(database, user, password):
    # Connect to the database and retrieve the addresses to which a delivery
    # message should be sent.
    connection = psycopg2.connect(database=database, user=user,
                                  password=password)
    connection.set_isolation_level(ISOLATION_LEVEL_SERIALIZABLE)
    cursor = connection.cursor()
    cursor.execute("""SELECT recipient FROM saved_mail_recipients
        WHERE delivery_id IS NULL
        GROUP BY recipient""")
    recipients = [x[0] for x in cursor.fetchall()]

    # Send a quarantine report to each recipient. Each report is generated
    # and sent out within a single database transaction, and we make five
    # attempts per user to send the report before giving up.
    random.seed()
    for recipient in recipients:
        attempt = 0
        while attempt < 5:
            try:
                _sendQuarantineReport(recipient, cursor)
                connection.commit()
                break
            except psycopg2.DatabaseError, e:
                connection.rollback()
                attempt += 1
                if attempt == 5:
                    print "Unable to send report to %s: %s" % (recipient, e)
                time.sleep(10);
    
def _sendQuarantineReport(recipient, cursor):
    # Determine the real recipient.
    cursor.execute(
        "SELECT delivery FROM quarantine_recipients WHERE %s ~ regexp",
        [recipient])
    if cursor.rowcount != 0:
        actualRecipient = cursor.fetchone()[0]
    else:
        actualRecipient = recipient
    
    # Retrieve the set of saved mail ids for this recipient.
    cursor.execute(
        """SELECT saved_mail_id FROM saved_mail_recipients
        WHERE recipient = %s AND delivery_id IS NULL""",
        [recipient])
    mailIds = [x[0] for x in cursor.fetchall()]
    
    # Retrieve the sender, subject and creation date.
    cursor.execute(
        """SELECT mail_from, extract_header('Subject', contents), created, id
        FROM saved_mail WHERE id IN (""" +
        ", ".join([str(x) for x in mailIds]) + 
        ") ORDER BY created")
    messages = cursor.fetchall()
    
    # Extract the domain name from the recipient and determine the name of the
    # mail server.
    domain = recipient[recipient.index("@") + 1 :]
    cursor.execute("SELECT display FROM domain_names WHERE domain = %s",
                   [domain]);
    if cursor.rowcount != 0:
        serverName = cursor.fetchone()[0]
    else:
        serverName = domain

    # Construct the message.
    headersTmpl = string.Template(headers)
    curDate = mx.DateTime.now()
    text = [headersTmpl.substitute(
        recipient=recipient,
        rfcdate=rfc822str(curDate),
        domain=domain,
        subjectDate=curDate.strftime("%m/%d/%Y %I:%M %p"))]
    preambleTmpl = string.Template(preamble)
    if len(messages) == 1:
        numMessages = '1 Message'
    else:
        numMessages = '%s Messages' % len(messages)
        
    text.append(
        preambleTmpl.substitute(recipient=recipient,
                                numMessages=numMessages,
                                serverName=serverName))
    rowTmpl = string.Template(rowText)
    i = 0
    for msg in messages:
        if i & 1 == 0:
            colour = "#FFFFFF"
        else:
            colour = "#EEEEEE"
        
        i += 1
        mailFrom, subject, msgDate, msgId = msg
        msgDate = msgDate.replace(microsecond=0)
        digest = md5.new()
        digest.update(mailFrom)
        digest.update(subject)
        digest.update(str(msgDate))
        digest.update(str(random.random()))
        deliveryId = digest.hexdigest()
        text.append(
            rowTmpl.substitute(
                mailFrom=mailFrom, subject=subject, msgDate=msgDate,
                deliveryId=deliveryId, colour=colour))
        cursor.execute(
            """UPDATE saved_mail_recipients SET delivery_id = %s
            WHERE recipient = %s AND saved_mail_id = %s""",
            (deliveryId, recipient, msgId))
        
    text.append(suffix)
    
    # Deliver the message.
    mailServer = smtplib.SMTP("localhost")
    sender = "do_not_reply@%s" % domain
    mailServer.sendmail(sender, actualRecipient, "".join(text),
                        ["BODY=8BITMIME"])
    mailServer.quit()
    
if __name__ == "__main__":
    main("spamassassin", "qmail", "38hb75")
