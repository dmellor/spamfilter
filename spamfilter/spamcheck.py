from subprocess import *
import socket
import re
import logging
import traceback
import email
from email.utils import parseaddr

from spamfilter.smtpproxy import SmtpProxy
from spamfilter.mixin import *
from spamfilter.model.spam import Spam, SpamRecipient, SpamTest
from spamfilter.model.virus import Virus, VirusRecipient
from spamfilter.model.greylist import create_greylist_class
from spamfilter.model.sentmail import SentMail
from spamfilter.model.autowhitelist import AutoWhitelist
from spamfilter.model.receivedmail import ReceivedMail

SPAM = '250 Message was identified as spam and has been quarantined'
HONEYPOT = '250 Message was sent to a honeypot address'
VIRUS = '250 Message contains a virus and has been quarantined'
UNKNOWN = '550 Unknown user'

Greylist = None


class DisabledCharsetTests(object):
    def __init__(self, value):
        charset, tests = value.split(None, 1)
        self.charset = charset.lower()
        self.tests = tests.split()


class SpamCheck(SmtpProxy, ConfigMixin):
    """
    This class checks a message against spamd for spam and clamd for viruses.
    """

    def __init__(self, config, **kws):
        global Greylist
        super(SpamCheck, self).__init__(**kws)
        self.read_config(config)
        self.session = create_session(
            self.get_config_item('database', 'dburi'), serializable=False)
        Greylist = create_greylist_class(
            self.get_config_item('greylist', 'interval', 30))
        self.trusted_ips = self.get_config_item_list('sent_mail', 'trusted_ips')
        self.pop_db = self.get_config_item('spamfilter', 'pop_db', None)
        self.host = self.get_config_item('spamfilter', 'host')
        self.disabled_tests = []
        num = 0
        while True:
            num += 1
            value = self.get_config_item(
                'spamfilter', 'charset_disabled_tests%s' % num, None)
            if not value:
                break

            self.disabled_tests.append(DisabledCharsetTests(value))

    def check_message(self, message):
        # First check if any of the recipients are honeypot addresses. If they
        # are then no spam checks will be performed.
        self.check_honeypot()

        # If the sender is whitelisted then we do not want to perform any
        # checks. This is to prevent quarantining mail that SpamAssassin
        # consistently and incorrectly flags as spam.
        whitelist_db = self.get_config_item('spamfilter', 'whitelist_db', None)
        if whitelist_db:
            if self.bounce:
                # First check the full address.
                mail_from = self.bounce.lower()
                if query_postfix_db(whitelist_db, mail_from):
                    return self.determine_whitelist_status()

                # Check the domain.
                domain = mail_from.index('@') + 1
                if query_postfix_db(whitelist_db, mail_from[domain:]):
                    return self.determine_whitelist_status()

            # Check if the HELO string is whitelisted.
            if query_postfix_db(whitelist_db, self.remote_host):
                return self.determine_whitelist_status()

            # If there is only a single recipient, then check if the recipient
            # is whitelisted. This is mainly to prevent bounce messages to a
            # dedicated bounce address from being flagged as spam, as automated
            # bounce messages can often trigger SpamAssassin's rules.
            recipients = self.get_unique_recipients()
            if len(recipients) == 1:
                if query_postfix_db(whitelist_db, recipients[0]):
                    return self.determine_whitelist_status()

        # The client is an external client - perform the spam and virus checks.
        message = ''.join(message)
        ok = False
        err_status = None
        try:
            ok = self.perform_checks(message)
            if self.bounce:
                received_mail = ReceivedMail(ip_address=self.remote_addr,
                                             email=self.bounce.lower(),
                                             is_spam=not ok)
                self.session.add(received_mail)

            self.session.commit()
        except Exception, exc:
            self.session.rollback()
            err_status = re.sub(r'\r?\n', ' ', str(exc))
            logging.info('spamcheck failed: %s', err_status)
            logging.info(traceback.format_exc())

        if err_status:
            self.error_response = "451 %s" % err_status

        return ok

    # If the message is from a whitelisted address and is addressed only to
    # honeypot recipients, then let the sender know by bouncing the message.
    def determine_whitelist_status(self):
        if self.is_to_honeypot and not self.non_honeypot_recipients:
            self.error_response = UNKNOWN
            return False
        else:
            return True

    def perform_checks(self, message):
        # If the message if being sent from this host, then do not perform any
        # checks.
        if self.is_sent_mail():
            return True

        # If the message is above a certain size, then automatically accept it.
        max_len = int(self.get_config_item('spamfilter', 'max_message_length'))
        if len(message) > max_len and not self.is_to_honeypot:
            return True

        ok = self.check_spam(message) and self.check_virus(message)

        # If the message is spam or contains a virus then we ensure that its
        # corresponding greylist entry, if any, is removed.
        if not ok:
            ip_address = '.'.join(self.remote_addr.split('.')[:3])
            query = self.session.query(Greylist)
            mail_from = self.bounce.lower() if self.bounce else None
            query = query.filter_by(mail_from=mail_from, ip_address=ip_address)
            recipients = self.get_unique_recipients()
            for recipient in recipients:
                entry = query.filter_by(rcpt_to=recipient).first()
                if entry:
                    self.session.delete(entry)

        return ok

    def check_spam(self, message):
        # Check the message and accept it if it is not spam.
        max_len = self.get_config_item('spamfilter', 'max_message_length')
        try:
            score, required, tests = self.check_spamassassin(message, max_len)
        except Exception, exc:
            error_message = re.sub(r'\r?\n', ' ', str(exc))
            logging.info('spam check failed: %s', error_message)
            return True

        # SpamAssassin does not deal well with some message character sets,
        # causing some tests to fire incorrectly. The spam score is adjusted
        # here by disabling the problem tests if they have fired.
        msg_obj = email.message_from_string(message)
        dkim_domain = get_dkim_domain(msg_obj, message)
        if dkim_domain and not is_dkim_verified(message):
            dkim_domain = ''

        charset = get_charset_from_message(msg_obj)
        disabled_tests = [x.tests for x in self.disabled_tests
                          if x.charset == charset]
        if disabled_tests:
            disabled_tests = disabled_tests[0]
            accepted_tests = []
            adjusted_score = 0
            for test in tests:
                if test[1] in disabled_tests:
                    adjusted_score += float(test[0])
                else:
                    accepted_tests.append(test)

            tests = accepted_tests
            score -= adjusted_score
            if adjusted_score != 0:
                # If the score needs to be adjusted then we must adjust
                # the auto-whitelist scores that were updated by
                # SpamAssassin.
                ips, helo = get_received_ips_and_helo(msg_obj, self.host)
                mail_from = parseaddr(
                    msg_obj['From'] or msg_obj['Return-Path'])[1].lower()
                query = self.session.query(AutoWhitelist)
                query = query.filter_by(email=mail_from, signedby=dkim_domain)
                processed_classbs = {}
                for ip in ips:
                    classb = '.'.join(ip.split('.')[:2])
                    if classb in processed_classbs:
                        continue

                    processed_classbs[classb] = True
                    record = query.filter_by(ip=classb).first()
                    if record:
                        record.totscore -= adjusted_score

        ok = score < required and not self.is_to_honeypot
        if not ok:
            # The message is spam. In case of false positives, the message is
            # quarantined.
            spam = Spam(bounce=self.bounce, ip_address=self.remote_addr,
                        helo=self.remote_host, contents=message, score=score,
                        tests=determine_spam_tests(tests),
                        honeypot=self.is_to_honeypot)
            recipients = self.get_unique_recipients()
            spam.recipients = [SpamRecipient(recipient=x) for x in recipients]
            self.session.add(spam)

            # Fix the AWL - this accounts for spam in which the envelope header
            # is different from the From: header, in which case SpamAssassin
            # will not update the entry corresponding to the envelope header. If
            # the AWL entry for the envelope header is below the spam threshold,
            # then this allows the message to avoid greylisting or blacklisting
            # in the policy check because it will pass the isAccepted method.
            self.fix_awl(msg_obj, dkim_domain, score)

            # Set the error response to be written to the mail log.
            self.error_response = HONEYPOT if self.is_to_honeypot else SPAM

        return ok

    def check_virus(self, message):
        # Check the message against the ClamAV server.
        host = self.get_config_item('spamfilter', 'clamav_server', 'localhost')
        port = self.get_config_item('spamfilter', 'clamav_port', 3310)
        timeout = self.get_config_item('spamfilter', 'clamav_timeout', 30)
        virus_type = check_clamav(message, host, port, timeout)
        if virus_type:
            # The message is a virus and must be quarantined.
            virus = Virus(bounce=self.bounce, helo=self.remote_host,
                          ip_address=self.remote_addr, contents=message,
                          virus=virus_type)
            recipients = self.get_unique_recipients()
            virus.recipients = [VirusRecipient(recipient=x)
                                for x in recipients]
            self.session.add(virus)

            # Set the error response to be written to the mail log.
            self.error_response = VIRUS
            return False
        else:
            return True

    def get_unique_recipients(self):
        recips = {}
        if self.is_to_honeypot:
            originals = self.non_honeypot_recipients
        else:
            originals = self.rcpt_to

        for recip in originals:
            recips[recip] = 1

        return recips.keys()

    def is_sent_mail(self):
        # If the remote IP address is a trusted IP address or is in the POP
        # before SMTP table, then we do not want to perform any checks as this
        # is mail that is being sent from this host.
        is_sent_mail = self.remote_addr in self.trusted_ips
        if not is_sent_mail and self.pop_db:
            is_sent_mail = query_postfix_db(self.pop_db, self.remote_addr)

        if is_sent_mail and self.bounce:
            mail_from = self.bounce.lower()
            query = self.session.query(SentMail).filter_by(sender=mail_from)
            recipients = self.get_unique_recipients()
            for recipient in recipients:
                record = query.filter_by(recipient=recipient).first()
                if record:
                    record.messages += 1
                else:
                    self.session.add(SentMail(sender=mail_from,
                                              recipient=recipient))

        return is_sent_mail

    def fix_awl(self, message, dkim_domain, score):
        # If the envelope sender is different from the address in the From:
        # header, then we update the AWL record for the envelope sender.
        header = parseaddr(
            message['From'] or message['Return-Path'])[1].lower()
        if self.bounce and header != self.bounce.lower():
            mail_from = self.bounce.lower()
            query = self.session.query(AutoWhitelist)
            classb = '.'.join(self.remote_addr.split('.')[:2])
            query = query.filter_by(email=mail_from, ip=classb,
                                    signedby=dkim_domain)
            record = query.first()
            if record:
                record.totscore += score
                record.count += 1
            else:
                record = AutoWhitelist(username='GLOBAL', email=mail_from,
                                       ip=classb, count=1, totscore=score,
                                       signedby=dkim_domain)
                self.session.add(record)

    def check_spamassassin(self, message, max_len, host=None):
        command = ['/usr/bin/spamc', '-R', '-x', '-s', str(max_len)]
        if host:
            command.extend(['-d', host])

        # Since Postfix does not prepend a Return-Path: header to the message
        # until it has delivered it to a mailbox we have to synthesise a
        # Return-Path: header here so that the SpamAssassin tests that depend on
        # it will fire.
        spamc = Popen(command, shell=False, stdin=PIPE, stdout=PIPE)
        spamc.stdin.write('Return-Path: <%s>\n' % (self.bounce or ''))
        spamc.stdin.write(message)
        spamc.stdin.close()
        output = []
        exit_code = 0
        while True:
            line = spamc.stdout.readline()
            if line == '':
                exit_code = spamc.wait()
                break

            output.append(line.rstrip())

        if exit_code != 0:
            raise Exception('spamc returned exit code %s' % exit_code)

        # Extract the score, and determine tests that fired from the output of
        # spamc.
        score, required = [float(x) for x in output.pop(0).split('/')]
        pattern = re.compile(r'^\s*(-?\d+\.?\d*)\s+(\S+)\s+(.*)')
        tests = []
        seen = False
        for line in output:
            if not seen and line.startswith('Content analysis details'):
                seen = True
                continue
            elif seen:
                match = pattern.search(line)
                if match:
                    test_score, test, description = match.groups()
                    description = description.strip()
                    tests.append((test_score, test, description))
                    continue

                if tests:
                    continuation = line.strip()
                    if continuation:
                        test_score, test, description = tests[-1]
                        description += ' ' + continuation
                        tests[-1] = (test_score, test, description)

        return score, required, tests

    def check_honeypot(self):
        self.is_to_honeypot = False
        self.non_honeypot_recipients = []
        honeypot_db = self.get_config_item('spamfilter', 'honeypot_access_db',
                                           None)
        if honeypot_db:
            for recipient in self.rcpt_to:
                if query_postfix_db(honeypot_db, recipient):
                    self.is_to_honeypot = True
                else:
                    self.non_honeypot_recipients.append(recipient)


def check_clamav(message, host, port, timeout):
    timeout = float(timeout)
    port = int(port)

    # Open a socket to the CLAMAV daemon.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.settimeout(timeout)
        s.sendall('STREAM\n')
        response = s.recv(1024)

        # Determine the port to connect to for the virus check.
        port = re.search(r'PORT\s+(\d+)', response).group(1)
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stream.connect((host, int(port)))
        stream.settimeout(timeout)
        stream.sendall(message)
        stream.close()

        # Read the response from the server.
        response = s.recv(1024)
        match = re.search(r'(\S+)\s+FOUND$', response)
        return match.group(1) if match else None
    except Exception, exc:
        error_message = re.sub(r'\r?\n', ' ', str(exc))
        logging.info('virus check failed: %s', error_message)
        return None


def determine_spam_tests(tests):
    scores, names, descriptions = zip(*tests)
    spam_tests = []
    for i in range(len(names)):
        # Some of the more esoteric SpamAssassin tests do not have a
        # description, in which case spamc will report the description as being
        # equal to the test name. For such tests we create a SpamTest object
        # with the description set to null.
        if names[i] != descriptions[i]:
            spam_tests.append(
                SpamTest(name=names[i], description=descriptions[i],
                         score=float(scores[i])))
        else:
            spam_tests.append(SpamTest(name=names[i], score=float(scores[i])))

    return spam_tests


def get_charset_from_message(message):
    charset = message.get_param('charset')
    try:
        if not charset:
            payload = message.get_payload()
            if isinstance(payload, list):
                for msg in payload:
                    charset = get_charset_from_message(msg)
                    if charset:
                        charset = charset.lower()
                        break
        else:
            charset = charset.lower()
    except:
        # If a charset could not be determined due to its declaration being
        # malformed then return an empty charset.
        return None

    return charset
