from subprocess import *
import re
import os
import sys
import logging
import traceback

from spamfilter.mixin import *
from spamfilter.model.spam import Spam
from spamfilter.model.greylist import create_greylist_class
from spamfilter.model.smtpdconnection import SmtpdConnection
from spamfilter.model.login import Login
from spamfilter.model.loginfailures import LoginFailure

UNKNOWN = re.compile(r'RCPT from ([^\[]+)\[([^\]]+)')
RECIPIENT = re.compile(r'to=<([^>]+)')
SENDER = re.compile(r'from=<([^>]+)')
CONNECT = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]$')
LOGIN = re.compile(r': LOGIN, user=([^,]+), ip=\[(.+)\]')
IP = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
FAILED_IP = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\: SASL')

Greylist = None


def become_daemon(pid_file):
    pid = os.fork()
    if pid:
        f = open(pid_file, 'w')
        f.write('%s\n' % pid)
        f.close()
        sys.exit()

    os.setsid()
    read_fd = os.open('/dev/null', os.O_RDONLY)
    write_fd = os.open('/dev/null', os.O_WRONLY)
    os.dup2(read_fd, 0)
    os.dup2(write_fd, 1)
    os.dup2(write_fd, 2)
    os.close(read_fd)
    os.close(write_fd)


class HoneyPot(ConfigMixin):
    """
    This class implements a daemon that reads the mail logs to determine when
    attempts are made to send messages to unknown addresses, and adds them to
    the honeypot address list as well as adding an entry to the spam table so
    that the contents of successive delivery attempts to a honeypot address are
    recorded in the spam table. This class also logs verified logins to the
    Courier IMAP/POP server, so that email from verified users is not passed
    through the spam filter.
    """

    def __init__(self, config):
        global Greylist
        self.read_config(config)
        Greylist = create_greylist_class(
            self.get_config_item('greylist', 'interval', 30))
        self.pid_file = self.get_config_item('honeypot', 'pid_file')

    def run(self):
        become_daemon(self.pid_file)
        try:
            self._run()
        except:
            logging.error(traceback.format_exc())

    def _run(self):
        log = Popen(['/usr/bin/tail', '-F', '/var/log/maillog'], stdout=PIPE)
        self.session = create_session(
            self.get_config_item('database', 'dburi'), serializable=False)
        while True:
            line = log.stdout.readline()
            if line == '':
                logging.error('Exiting - lost connection to child')
                os._exit(1)

            if 'postfix/smtpd' in line and 'User unknown' in line:
                match = UNKNOWN.search(line)
                if match:
                    helo = match.group(1)
                    if helo == 'unknown':
                        helo = None

                    ip_address = match.group(2)
                    match = RECIPIENT.search(line)
                    if match:
                        recipient = match.group(1).lower()
                    else:
                        logging.error('Could not determine recipient')
                        continue

                    match = SENDER.search(line)
                    if match:
                        sender = match.group(1)
                    else:
                        logging.error('Could not determine sender')
                        continue

                    self.process_honeypot(helo, ip_address, recipient, sender)
            elif 'postfix/smtpd' in line and ' connect from ' in line:
                match = CONNECT.search(line)
                if match:
                    self.process_connect(match.group(1))
            elif 'imapd' in line or 'pop3d' in line:
                match = LOGIN.search(line)
                if match:
                    user = match.group(1)
                    ip = match.group(2)
                    ip_match = IP.search(ip)
                    if ip_match:
                        ip = ip_match.group(1)
                        login = Login(username=user, ip_address=ip)
                        self.session.add(login)
                        self.session.commit()
            elif 'SASL LOGIN authentication failed:' in line:
                match = FAILED_IP.search(line)
                if match:
                    ip = match.group(1)
                    login_failure = LoginFailure(ip_address=ip)
                    self.session.add(login_failure)
                    self.session.commit()

    def process_honeypot(self, helo, ip_address, recipient, sender):
        spam = Spam(bounce=sender, ip_address=ip_address, helo=helo,
                    honeypot=True)
        self.session.add(spam)

        # Remove the greylist entries for the class C network to ensure that
        # greylist timeouts have to be restarted once a honeypot address has
        # been identified.
        classc = '.'.join(ip_address.split('.')[:3])
        query = self.session.query(Greylist).filter_by(classc=classc)
        for entry in query.all():
            self.session.delete(entry)

        self.session.commit()

        db = open(self.get_config_item('honeypot', 'honeypot_db'), 'a')
        db.write('%s %s\n' % (recipient,
                              self.get_config_item('honeypot', 'address')))
        db.close()
        db = open(self.get_config_item('honeypot', 'honeypot_access_db'), 'a')
        db.write('%s ok\n' % recipient)
        db.close()

        command = Popen(['/usr/bin/make', '-C',
                         self.get_config_item('honeypot', 'postfix_dir')])
        status = command.wait()
        if status:
            logging.error('Error code %s from make command' % status)

    def process_connect(self, ip_address):
        if ip_address != '127.0.0.1':
            classc = '.'.join(ip_address.split('.')[:3])
            smtpd_connection = SmtpdConnection(ip_address=ip_address,
                                               classc=classc)
            self.session.add(smtpd_connection)
            self.session.commit()
