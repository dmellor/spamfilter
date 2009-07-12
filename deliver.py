#!/usr/bin/python2.6
import os
import sys
import site
import smtplib
import email
from email.utils import parseaddr

deployment_dir = sys.path[0]
site.addsitedir('%s/lib/python2.6/site-packages' % deployment_dir)

from spamfilter.mixin import *
from spamfilter.model.spam import Spam, SpamRecipient
from spamfilter.model.autowhitelist import AutoWhitelist
from spamfilter.report import translate
from sqlalchemy import text

class Deliver(ConfigMixin):
    def __init__(self):
        self.readConfig(os.path.join(deployment_dir, 'config.ini'))

    def process(self):
        path_info = os.getenv('PATH_INFO')
        if path_info[0] != '/':
            _invalidId()

        delivery_id = path_info[1:]
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.host = self.getConfigItem('spamfilter', 'host')
        try:
            method = os.getenv('REQUEST_METHOD')
            if method != 'GET' and method != 'POST':
                sys.exit()

            query = self.session.query(SpamRecipient).filter_by(
                delivery_id=delivery_id)
            spam_recipient = query.first()
            if not spam_recipient:
                _invalidId()

            spam = self.session.query(Spam).get(spam_recipient.spam_id)
            if method == 'GET':
                _confirm('http://' + os.getenv('SERVER_NAME') +
                         os.getenv('SCRIPT_NAME') + os.getenv('PATH_INFO'),
                         spam)
            else:
                self.deliver(spam, spam_recipient)

            self.session.commit()
        except:
            self.session.rollback()
            raise

    def deliver(self, spam, spam_recipient):
        # Determine the real recipient.
        connection = self.session.connection()
        statement = text(
            'SELECT delivery FROM quarantine_recipients WHERE :x ~ regexp')
        result = connection.execute(
            statement, x=spam_recipient.recipient).fetchone()
        if result:
            recipient = result[0]
        else:
            recipient = spam_recipient.recipient

        # Delete the entry in the spam_recipients table and the message if
        # the number of spam recipients has dropped to zero.
        self.session.delete(spam_recipient)
        query = self.session.query(SpamRecipient)
        if query.filter_by(spam_id=spam_recipient.spam_id).count() == 0:
            self.session.delete(spam)

        # Adjust the auto-whitelist entry. Care must be taken not to include
        # the value of the AWL test if that fired for the message, as the
        # increment added to the total score in the auto_whitelist table will
        # not have included the score for the AWL test.
        if 'AWL' in [x.name for x in spam.tests]:
            adjustment = reduce(lambda x, y: x + y,
                                [x.score for x in spam.tests
                                 if x.name != 'AWL'])
        else:
            adjustment = spam.score

        message = email.message_from_string(spam.contents)
        mail_from = parseaddr(message['From'] or message['Return-Path'])[1]
        query = self.session.query(AutoWhitelist).filter_by(email=mail_from)
        ips, helo = getReceivedIPsAndHelo(message, self.host)
        processed_classbs = {}
        for ip in ips:
            classb = '.'.join(ip.split('.')[:2])
            if classb not in processed_classbs:
                processed_classbs[classb] = True
                record = query.filter_by(ip=classb).first()
                if record:
                    record.totscore -= adjustment

        # Deliver the message.
        mailServer = smtplib.SMTP('localhost')
        mailServer.sendmail(spam.mail_from, recipient, spam.contents,
                            ['BODY=8BITMIME'])
        mailServer.quit()

        _success()

def _confirm(url, spam):
    print 'Content-Type: text/html; charset=utf-8'
    print
    print '<html><head><title>Confirm Message Delivery</title></head>'
    print '<body><font size="+1">'
    print '<br>From: %s' % spam.mail_from
    print '<br>Subject: %s' % translate(spam.subject).encode('utf8')
    print '<br><br>This message has been quarantined for the following reasons'
    print '<ul>'
    for test in spam.tests:
        if test.description:
            print '<li>%s</li>' % test.description

    print '</ul></font>'
    print '<h2>Click the button to deliver the message to your mailbox.</h2>'
    print '<form method="POST" enctype="application/x-www-form-urlencoded"'
    print 'action="%s"' % url, '>'
    print '<input type="submit" value="Deliver message"></form></body></html>'

def _invalidId():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Invalid Message ID</title></head>"
    print "<body><h2>An invalid message id was specified.</h2></body></html>"
    sys.exit()
    
def _success():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Message Queued For Delivery</title></head>"
    print "<body>"
    print "<h2>Your message has been queued for delivery to your mailbox.</h2>"
    print "</body></html>"

if __name__ == "__main__":
    Deliver().process()
    sys.exit()
