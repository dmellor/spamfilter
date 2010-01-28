import os
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
from spamfilter.model.greylist import createGreylistClass
from spamfilter.model.sentmail import SentMail
from spamfilter.model.autowhitelist import AutoWhitelist

SPAM = '250 Message was identified as spam and has been quarantined'
VIRUS = '250 Message contains a virus and has been quarantined'

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
        self.readConfig(config)
        self.session = createSession(
            self.getConfigItem('database', 'dburi'), serializable=False)
        Greylist = createGreylistClass(
            self.getConfigItem('greylist', 'interval', 30))
        self.trusted_ips = self.getConfigItemList('sent_mail', 'trusted_ips')
        self.pop_db = self.getConfigItem('spamfilter', 'pop_db', None)
        self.host = self.getConfigItem('spamfilter', 'host')
        self.getDisabledCharsetTests()

    def getDisabledCharsetTests(self):
        self.disabled_tests = []
        num = 0
        while True:
            num += 1
            value = self.getConfigItem(
                'spamfilter', 'charset_disabled_tests%s' % num, None)
            if not value:
                break

            self.disabled_tests.append(DisabledCharsetTests(value))

    def checkMessage(self, message):
        # If the sender is whitelisted then we do not want to perform any
        # checks. This is to prevent quarantining mail that SpamAssassin
        # consistently and incorrectly flags as spam.
        whitelist_db = self.getConfigItem('spamfilter', 'whitelist_db', None)
        if whitelist_db:
            if self.mail_from:
                # First check the full address.
                if queryPostfixDB(whitelist_db, self.mail_from):
                    return True

                # Check the domain.
                domain = self.mail_from.index('@') + 1
                if queryPostfixDB(whitelist_db, self.mail_from[domain:]):
                    return True

            # Check if the HELO string is whitelisted.
            if queryPostfixDB(whitelist_db, self.remote_host):
                return True

        # The client is an external client - perform the spam and virus checks.
        message = ''.join(message)
        ok = False
        err_status = None
        try:
            ok = self.performChecks(message)
            self.session.commit()
        except Exception, exc:
            self.session.rollback()
            err_status = re.sub(r'\r?\n', ' ', str(exc))
            logging.info('spamcheck failed: %s', err_status)
            logging.info(traceback.format_exc())
                           
        if err_status:
            self.error_response = "451 %s" % err_status
            
        return ok

    def performChecks(self, message):
        # If the message if being sent from this host, then do not perform any
        # checks.
        if self.isSentMail():
            return True

        # If the message is above a certain size, then automatically accept it.
        max_len = int(self.getConfigItem('spamfilter', 'max_message_length'))
        if len(message) > max_len:
            return True

        ok = self.checkSpam(message) and self.checkVirus(message)

        # If the message is spam or contains a virus then we ensure that its
        # corresponding greylist entry, if any, is removed.
        if not ok:
            ip_address = '.'.join(self.remote_addr.split('.')[:3])
            query = self.session.query(Greylist)
            query = query.filter_by(mail_from=self.mail_from,
                                    ip_address=ip_address)
            recipients = self.getUniqueRecipients()
            for recipient in recipients:
                entry = query.filter_by(rcpt_to=recipient).first()
                if entry:
                    self.session.delete(entry)

        return ok

    def checkSpam(self, message):
        # Check the message and accept it if it is not spam.
        max_len = self.getConfigItem('spamfilter', 'max_message_length')
        score, required, tests = checkSpamassassin(message, max_len)

        # SpamAssassin does not deal well with some message character sets,
        # causing some tests to fire incorrectly. The spam score is adjusted
        # here by disabling the problem tests if they have fired.
        msg_obj = email.message_from_string(message)
        charset = getCharsetFromMessage(msg_obj)
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
                ips, helo = getReceivedIPsAndHelo(msg_obj, self.host)
                mail_from = parseaddr(
                    msg_obj['From'] or msg_obj['Return-Path'])[1].lower()
                query = self.session.query(AutoWhitelist)
                query = query.filter_by(email=mail_from)
                processed_classbs = {}
                for ip in ips:
                    classb = '.'.join(ip.split('.')[:2])
                    if classb in processed_classbs:
                        continue

                    processed_classbs[classb] = True
                    record = query.filter_by(ip=classb).first()
                    if record:
                        record.totscore -= adjusted_score

        ok = score < required
        if not ok:
            # The message is spam. In case of false positives, the message is
            # quarantined.
            spam = Spam(mail_from=self.mail_from, ip_address=self.remote_addr,
                        helo=self.remote_host, contents=message, score=score,
                        tests=determineSpamTests(self.session, tests))
            recipients = self.getUniqueRecipients()
            spam.recipients = [SpamRecipient(recipient=x) for x in recipients]
            self.session.add(spam)

            # Fix the AWL - this accounts for spam in which the envelope header
            # is different from the From: header, in which case SpamAssassin
            # will not update the entry corresponding to the envelope header. If
            # the AWL entry for the envelope header is below the spam threshold,
            # then this allows the message to avoid greylisting or blacklisting
            # in the policy check because it will pass the isAccepted method.
            self.fixAWL(msg_obj, score)

            # Set the error response to be written to the mail log.
            self.error_response = SPAM

        return ok

    def checkVirus(self, message):
        # Check the message against the ClamAV server.
        host = self.getConfigItem('spamfilter', 'clamav_server', 'localhost')
        port = self.getConfigItem('spamfilter', 'clamav_port', 3310)
        timeout = self.getConfigItem('spamfilter', 'clamav_timeout', 30)
        virus_type = checkClamav(message, host, port, timeout)
        if virus_type:
            # The message is a virus and must be quarantined.
            virus = Virus(mail_from=self.mail_from, helo=self.remote_host,
                          ip_address=self.remote_addr, contents=message,
                          virus=virus_type)
            recipients = self.getUniqueRecipients()
            virus.recipients = [VirusRecipient(recipient=x)
                                for x in recipients]
            self.session.add(virus)

            # Set the error response to be written to the mail log.
            self.error_response = VIRUS
            return False
        else:
            return True

    def getUniqueRecipients(self):
        recips = {}
        for recip in self.rcpt_to:
            recips[recip] = 1
        
        return recips.keys()

    def isSentMail(self):
        # If the remote IP address is a trusted IP address or is in the POP
        # before SMTP table, then we do not want to perform any checks as this
        # is mail that is being sent from this host.
        is_sent_mail = self.remote_addr in self.trusted_ips
        if not is_sent_mail and self.pop_db:
            is_sent_mail = queryPostfixDB(self.pop_db, self.remote_addr)

        if is_sent_mail and self.mail_from:
            query = self.session.query(SentMail).filter_by(
                sender=self.mail_from)
            recipients = self.getUniqueRecipients()
            for recipient in recipients:
                record = query.filter_by(recipient=recipient).first()
                if record:
                    record.messages += 1
                else:
                    self.session.add(SentMail(sender=self.mail_from,
                                              recipient=recipient))

        return is_sent_mail

    def fixAWL(self, message, score):
        # If the envelope sender is different from the address in the From:
        # header, then we update the AWL record for the envelope sender.
        header = parseaddr(
            message['From'] or message['Return-Path'])[1].lower()
        if header != self.mail_from:
            query = self.session.query(AutoWhitelist)
            classb = '.'.join(self.remote_addr.split('.')[:2])
            record = query.filter_by(email=self.mail_from, ip=classb).first()
            if record:
                record.totscore += score
                record.count += 1
            else:
                record = AutoWhitelist(username='GLOBAL', email=self.mail_from,
                                       ip=classb, count=1, totscore=score)
                self.session.add(record)

def checkSpamassassin(message, max_len, host=None):
    command = ['/usr/bin/spamc', '-R', '-x', '-s', str(max_len)]
    if host:
        command.extend(['-d', host])
        
    spamc = Popen(command, shell=False, stdin=PIPE, stdout=PIPE)
    spamc.stdin.write(message)
    spamc.stdin.close()
    output = []
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
    continuation = re.compile(r'^\s*\b([^\r\n]*)')
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
                match = continuation.search(line)
                if match:
                    test_score, test, description = tests[-1]
                    description += ' ' + match.group(1).strip()
                    tests[-1] = (test_score, test, description)

    return score, required, tests

def checkClamav(message, host, port, timeout):
    timeout = float(timeout)
    port = int(port)

    # Open a socket to the CLAMAV daemon.
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

def determineSpamTests(session, tests):
    scores, names, descriptions = zip(*tests)
    spam_tests = []
    query = session.query(SpamTest)
    for i in range(len(names)):
        # Some of the more esoteric SpamAssassin tests do not have a
        # description, in which case spamc will report the description as being
        # equal to the test name. For such tests we create a SpamTest object
        # with the description set to null if the test is a new test. If an
        # existing test does not have a description but spamc now reports a
        # description for it then we update the existing test.
        spam_test = query.filter_by(name=names[i]).first()
        if spam_test:
            if (spam_test.description is None and
                names[i] != descriptions[i]):
                spam_test.description = descriptions[i]

            # Update the test's score if the saved score differs from the
            # reported score.
            if spam_test.score != scores[i]:
                spam_test.score = scores[i]

            spam_tests.append(spam_test)
        else:
            if names[i] != descriptions[i]:
                test = SpamTest(name=names[i], description=descriptions[i],
                                score=float(scores[i]))
            else:
                test = SpamTest(name=names[i], score=float(scores[i]))

            spam_tests.append(test)

    return spam_tests

def getCharsetFromMessage(message):
    charset = message.get_param('charset')
    if not charset:
        payload = message.get_payload()
        if isinstance(payload, list):
            for msg in payload:
                charset = getCharsetFromMessage(msg)
                if charset:
                    charset = charset.lower()
                    break
    else:
        charset = charset.lower()

    return charset
