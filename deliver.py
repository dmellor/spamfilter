import os
import sys
import smtplib
import email
from email.utils import parseaddr
from spamfilter.mixin import *
from spamfilter.model.spam import Spam, SpamRecipient
from spamfilter.model.autowhitelist import AutoWhitelist
from spamfilter.mixin import translate, get_body_type_charset


class Deliver(ConfigMixin):
    def __init__(self):
        self.read_config('config.ini')

    # noinspection PyAttributeOutsideInit
    def process(self):
        path_info = os.getenv('PATH_INFO')
        if path_info[0] != '/':
            invalid_id()

        delivery_id = path_info[1:]
        self.session = create_session(self.get_config_item('database', 'dburi'))
        self.host = self.get_config_item('spamfilter', 'host')
        try:
            method = os.getenv('REQUEST_METHOD')
            if method != 'GET' and method != 'POST':
                sys.exit()

            query = self.session.query(SpamRecipient).filter_by(
                delivery_id=delivery_id)
            spam_recipient = query.first()
            if not spam_recipient:
                invalid_id()

            spam = self.session.query(Spam).get(spam_recipient.spam_id)
            if method == 'GET':
                confirm('http://' + os.getenv('SERVER_NAME') +
                        os.getenv('SCRIPT_NAME') + os.getenv('PATH_INFO'),
                        spam)
            else:
                self.deliver(spam, spam_recipient)

            self.session.commit()
        except:
            self.session.rollback()
            raise

    # noinspection PyShadowingNames
    def deliver(self, spam, spam_recipient):
        # Retrieve the contents before deleting the message, as the contents
        # are deferred and cannot be retrieved after the deletion (SQLAlchemy
        # enters an infinite loop instead of throwing an exception).
        contents = spam.contents
        tests = spam.tests

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
        if 'AWL' in [x.name for x in tests]:
            adjustment = reduce(lambda x, y: x + y,
                                [x.score for x in tests if x.name != 'AWL'])
        else:
            adjustment = spam.score

        message = email.message_from_string(contents)
        mail_from = parseaddr(
            message['From'] or message['Return-Path'])[1].lower()
        query = self.session.query(AutoWhitelist).filter_by(email=mail_from)
        ips, helo = get_received_ips_and_helo(message, self.host)
        processed_classbs = {}
        for ip in ips:
            classb = '.'.join(ip.split('.')[:2])
            if classb not in processed_classbs:
                processed_classbs[classb] = True
                record = query.filter_by(ip=classb).first()
                if record:
                    record.totscore -= adjustment

        # Deliver the message.
        mail_server = smtplib.SMTP('localhost')
        mail_server.sendmail(spam.bounce, spam_recipient.recipient, contents,
                             ['BODY=8BITMIME'])
        mail_server.quit()
        success()


def confirm(url, spam):
    print 'Content-Type: text/html; charset=utf-8'
    print
    print '<html><head><title>Confirm Message Delivery</title></head>'
    print '<body><font size="+1">'
    if spam.bounce:
        print '<br>From: %s' % spam.bounce

    print '<br>Subject: %s' % translate(spam.subject).encode('utf8')
    reason = 'reasons' if len(spam.tests) > 1 else 'reason'
    print '<br><br>This message has been quarantined for the following %s:' % \
        reason
    print '<ul>'
    seen = {}
    for test in spam.tests:
        if test.description and test.description not in seen:
            print '<li>%s</li>' % test.description
            seen[test.description] = True

    print '</ul>'
    print '<br>The contents of the message are:'
    print '</font>'
    print '<table border="1"><tr>'
    print '<td><pre>%s</pre></td>' % extract_message_body(spam.contents)
    print '</tr></table>'
    print '<h2>Click the button to deliver the message to your mailbox.</h2>'
    print '<form method="POST" enctype="application/x-www-form-urlencoded"'
    print 'action="%s"' % url, '>'
    print '<input type="submit" value="Deliver message"></form></body></html>'


def extract_message_body(contents):
    message = email.message_from_string(contents)
    body, content_type, charset = get_body_type_charset(message)
    if charset:
        try:
            body = body.decode(charset).encode('utf8')
        except UnicodeDecodeError:
            # If the email was badly encoded we simply use the unmodified body.
            pass

    if content_type == 'text/html':
        from subprocess import Popen, PIPE
        command = ['/usr/bin/lynx', '-stdin', '-dump']
        env = os.environ.copy()
        env['HOME'] = '/tmp'
        lynx = Popen(command, shell=False, stdin=PIPE, stdout=PIPE, env=env)
        lynx.stdin.write(body)
        lynx.stdin.close()
        body = ''.join(lynx.stdout.readlines())
        lynx.wait()

    return fix_long_paragraphs(body)


def fix_long_paragraphs(body):
    from textwrap import TextWrapper
    wrapper = TextWrapper(width=120, break_long_words=False)
    lines = body.splitlines()
    modified_lines = []
    num_lines = len(lines)
    for i in xrange(num_lines):
        curlen = len(lines[i].strip())
        if curlen != 0:
            if i == 0:
                prev_clear = True
            else:
                prev_clear = len(lines[i - 1].strip()) == 0

            if i == num_lines - 1:
                next_clear = True
            else:
                next_clear = len(lines[i + 1].strip()) == 0

            if prev_clear and next_clear:
                try:
                    line = lines[i].decode('utf8')
                    modified_lines.extend([x.encode('utf8')
                                           for x in wrapper.wrap(line)])
                except UnicodeDecodeError:
                    modified_lines.append(lines[i])
            else:
                modified_lines.append(lines[i])
        else:
            modified_lines.append('')

    return '\n'.join(modified_lines)


def invalid_id():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Invalid Message ID</title></head>"
    print "<body><h2>An invalid message id was specified.</h2></body></html>"
    sys.exit()


def success():
    print "Content-Type: text/html"
    print
    print "<html><head><title>Message Queued For Delivery</title></head>"
    print "<body>"
    print "<h2>Your message has been queued for delivery to your mailbox.</h2>"
    print "</body></html>"


if __name__ == "__main__":
    Deliver().process()
    sys.exit()
