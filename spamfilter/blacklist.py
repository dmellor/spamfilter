from spamfilter.policy import ACCEPTED
from spamfilter.greylist import GreylistPolicy
from spamfilter.model.spam import Spam, spam_table
from spamfilter.model.greylist import create_greylist_class
from spamfilter.model.smtpdconnection import SmtpdConnection
from spamfilter.mixin import query_postfix_db
from sqlalchemy.sql import select, func, text

SOFT_REJECTED = 'defer_if_permit Spam has recently been received from %s'
HARD_REJECTED = 'reject Spam has recently been received from %s'
SOFT_CLASSC_REJECTED = \
    'defer_if_permit Spam has recently been received from the %s network'
HARD_CLASSC_REJECTED = \
    'reject Spam has recently been received from the %s network'
SUSPICIOUS_REJECTED = \
    'defer_if_permit Suspicious connection attempts from the %s network'

OK = 0
SOFT = 1
HARD = 2


class BlacklistPolicy(GreylistPolicy):
    def __init__(self, manager):
        super(BlacklistPolicy, self).__init__(manager)
        self.soft_threshold = int(manager.get_config_item(
            'blacklist', 'soft_threshold', 1))
        self.hard_threshold = int(manager.get_config_item(
            'blacklist', 'hard_threshold', 3))
        self.soft_classc_threshold = int(manager.get_config_item(
            'blacklist', 'soft_classc_threshold', 2))
        self.hard_classc_threshold = int(manager.get_config_item(
            'blacklist', 'hard_classc_threshold', 5))
        self.smtpd_connection_interval = int(manager.get_config_item(
            'smtpd_connection', 'interval', 60))
        self.suspicious_classc_threshold = int(manager.get_config_item(
            'smtpd_connection', 'suspicious_classc_threshhold', 10))
        self.suspicious_sibling_address_threshold = int(manager.get_config_item(
            'smtpd_connection', 'suspicious_sibling_address_threshold', 2))
        self.whitelist_remote_senders = manager.get_config_item(
            'smtpd_connection', 'whitelist_remote_senders', None)

    # noinspection PyAttributeOutsideInit
    def load_greylist_class(self):
        self.greylist_class = create_greylist_class(
            self.manager.get_config_item('blacklist', 'interval', 720))

    def process_request(self):
        rcpt_to, mail_from, ip_address = self.get_greylist_tuple()

        # First test - check if the IP address or host name is blacklisted.
        ip_num, helo_num = self.get_blacklist_thresholds()
        if ip_num >= helo_num:
            num = ip_num
            parameter = self.manager.get('client_address')
        else:
            num = helo_num
            parameter = self.manager.get('helo_name')

        if num >= self.hard_threshold:
            status1 = HARD_REJECTED % parameter
            level1 = HARD
        elif num >= self.soft_threshold:
            status1 = SOFT_REJECTED % parameter
            level1 = SOFT
        else:
            status1 = ACCEPTED
            level1 = OK

        # Second test - check if the class C network is blacklisted.
        status2 = ACCEPTED
        level2 = OK
        classc_count, distinct_count = self.get_classc_spam_count(ip_address)
        if distinct_count > 1:
            if classc_count >= self.hard_classc_threshold:
                status2 = HARD_CLASSC_REJECTED % get_network_block(ip_address)
                level2 = HARD
            elif classc_count >= self.soft_classc_threshold:
                status2 = SOFT_CLASSC_REJECTED % get_network_block(ip_address)
                level2 = SOFT

        # Determine the most restrictive level.
        if level1 >= level2:
            status = status1
            level = level1
        else:
            status = status2
            level = level2

        if level != OK:
            return self.greylist(rcpt_to, mail_from, ip_address, status)

        # If the sender is whitelisted then do not perform any more checks.
        if self.whitelist_remote_senders and query_postfix_db(
                self.whitelist_remote_senders,
                self.manager.get('reverse_client_name')):
            return ACCEPTED

        # Third test - check for suspicious activity from class C networks.
        classc = '.'.join(ip_address.split('.')[:3])
        interval = "now() - created <= interval '%s minutes'" % \
                   self.smtpd_connection_interval
        query = self.manager.session.query(SmtpdConnection).filter(
            SmtpdConnection.classc == classc).filter(text(interval))
        num_classc = query.count()
        if num_classc >= self.suspicious_classc_threshold:
            num_siblings = self.manager.session.query(
                func.count(SmtpdConnection.ip_address.distinct())).filter(
                SmtpdConnection.classc == classc).filter(
                SmtpdConnection.ip_address != ip_address).filter(
                text(interval)).one()[0]
            if num_siblings >= self.suspicious_sibling_address_threshold:
                return SUSPICIOUS_REJECTED % get_network_block(ip_address)

        return ACCEPTED

    def get_blacklist_thresholds(self):
        query = self.manager.session.query(Spam)
        ip_address = self.manager.get('client_address')
        ip_num = query.filter_by(ip_address=ip_address).count()
        helo = self.manager.get('helo_name')
        helo_num = query.filter_by(helo=helo).count()
        return ip_num, helo_num

    def get_classc_spam_count(self, ip_address):
        classc = '.'.join(ip_address.split('.')[:3])
        classc = '%s.%%' % classc
        query = select([func.count(spam_table.c.ip_address),
                        func.count(spam_table.c.ip_address.distinct())],
                       spam_table.c.ip_address.like(classc))
        connection = self.manager.session.connection()
        return connection.execute(query).fetchone()


def get_network_block(ip_address):
    octets = ip_address.split('.')[:3]
    return '%s.0/24' % '.'.join(octets)
