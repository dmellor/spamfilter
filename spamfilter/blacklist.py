from spamfilter.policy import ACCEPTED
from spamfilter.greylist import GreylistPolicy
from spamfilter.model.spam import Spam, spam_table
from spamfilter.model.greylist import createGreylistClass
from sqlalchemy.sql import select, func

SOFT_REJECTED = 'defer_if_permit Spam has recently been received from %s'
HARD_REJECTED = 'reject Spam has recently been received from %s'
SOFT_CLASSC_REJECTED = \
    'defer_if_permit Spam has recently been received from the %s network'
HARD_CLASSC_REJECTED = \
    'reject Spam has recently been received from the %s network'

OK = 0
SOFT = 1
HARD = 2

class BlacklistPolicy(GreylistPolicy):
    def __init__(self, manager):
        super(BlacklistPolicy, self).__init__(manager)
        self.soft_threshold = int(manager.getConfigItem(
            'blacklist', 'soft_threshold', 1))
        self.hard_threshold = int(manager.getConfigItem(
            'blacklist', 'hard_treshold', 3))
        self.soft_classc_threshold = int(manager.getConfigItem(
            'blacklist', 'soft_classc_threshold', 2))
        self.hard_classc_threshold = int(manager.getConfigItem(
            'blacklist', 'hard_classc_threshold', 5))

    def loadGreylistClass(self):
        self.greylist_class = createGreylistClass(
            self.manager.getConfigItem('blacklist', 'interval', 720))

    def processRequest(self):
        rcpt_to, mail_from, ip_address = self.getGreylistTuple()

        # First test - check if the IP address or host name is blacklisted.
        ip_num, helo_num = self.getBlacklistThresholds()
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
        classc_count, distinct_count = self.getClasscSpamCount(ip_address)
        if distinct_count > 1:
            if classc_count >= self.hard_classc_threshold:
                status2 = HARD_CLASSC_REJECTED % getNetworkBlock(ip_address)
                level2 = HARD
            elif classc_count >= self.soft_classc_threshold:
                status2 = SOFT_CLASSC_REJECTED % getNetworkBlock(ip_address)
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
        else:
            return ACCEPTED

    def getBlacklistThresholds(self):
        query = self.manager.session.query(Spam)
        ip_address = self.manager.get('client_address')
        ip_num = query.filter_by(ip_address=ip_address).count()
        helo = self.manager.get('helo_name')
        helo_num = query.filter_by(helo=helo).count()
        return ip_num, helo_num

    def getClasscSpamCount(self, ip_address):
        classc = '.'.join(ip_address.split('.')[:3])
        classc = '%s.%%' % classc
        query = select([func.count(spam_table.c.ip_address),
            func.count(spam_table.c.ip_address.distinct())],
            spam_table.c.ip_address.like(classc))
        connection = self.manager.session.connection()
        return connection.execute(query).fetchone()

def getNetworkBlock(ip_address):
    octets = ip_address.split('.')[:3]
    octets.append('0')
    return '%s/24' % '.'.join(octets)
