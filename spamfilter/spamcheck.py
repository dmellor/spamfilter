from subprocess import *
import socket
import re
import time
import logging

from spamfilter.smtpproxy import SmtpProxy
from spamfilter.mixin import *
from spamfilter.model.spam import Spam, SpamRecipient
from spamfilter.model.virus import Virus, VirusRecipient
from spamfilter.model.greylist import createGreylistClass

SPAM = '250 Message was identified as spam and has been quarantined'
VIRUS = '250 Message contains a virus and has been quarantined'

Greylist = None

class SpamCheck(SmtpProxy, ConfigMixin):
    """
    This class checks a message against spamd for spam and clamd for viruses.
    """
    def __init__(self, config, **kws):
        global Greylist
        super(SpamCheck, self).__init__(**kws)
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        Greylist = createGreylistClass(
            self.getConfigItem('greylist', 'interval', 30))

    def checkMessage(self, message):
        # If the remote address is in the POP before SMTP table, then we do not
        # want to perform any checks.
        pop_db = self.getConfigItem('spamfilter', 'pop_db', None)
        if pop_db and queryPostfixDB(pop_db, self.remote_addr):
            return True

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
        retries = 0
        num_retries = int(self.getConfigItem('general', 'retries', 2))
        message = ''.join(message)
        ok = False
        while retries < num_retries:
            err_status = None
            try:
                ok = self.performChecks(message)
                self.session.commit()
                break
            except Exception, exc:
                self.session.rollback()
                self.session.clear()
                err_status = re.sub(r'\r?\n', ' ', str(exc))
                logging.info('spamcheck failed: %s', err_status)
                retries += 1
                wait_time = int(self.getConfigItem('general', 'wait', 5))
                logging.info('sleeping for %s seconds', wait_time)
                time.sleep(wait_time)
                           
        if err_status:
            self.error_response = "451 %s" % err_status
            
        return ok

    def performChecks(self, message):
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
        ok, score, tests = checkSpamassassin(message)
        if not ok:
            # The message is spam. In case of false positives, the message is
            # quarantined.
            spam = Spam(mail_from=self.mail_from, ip_address=self.remote_addr,
                        helo=self.remote_host, contents=message, score=score,
                        tests=tests)
            recipients = self.getUniqueRecipients()
            spam.recipients = [SpamRecipient(recipient=x) for x in recipients]
            self.session.save(spam)

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
            self.session.save(virus)

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

def checkSpamassassin(message, host=None):
    command = ['/usr/bin/spamc', '-R', '-x']
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

    # Extract the score, and determine if the message has passed.
    score, required = [float(x) for x in output.pop(0).split('/')]
    if score < required:
        return True, score, None

    # The message is spam. We extract the tests from the rest of the output
    # from spamc.
    pattern = re.compile(r'^\s*[\d\.]+\s+(\S+)')
    tests = []
    seen = False
    for line in output:
        if not seen and line.startswith('Content analysis details'):
            seen = True
            continue
        elif seen:
            match = pattern.search(line)
            if match:
                tests.append(match.group(1))

    return False, score, ','.join(tests)

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
