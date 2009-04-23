from spamfilter.policy import ACCEPTED
from spamfilter.greylist import GreylistPolicy
from spamfilter.model.spam import Spam
from spamfilter.model.greylist import createGreylistClass

SOFT_REJECTED = 'defer_if_permit Spam has recently been received from %s'
HARD_REJECTED = 'reject Spam has recently been received from %s'
CLASSC_REJECTED = \
    'defer_if_permit Spam has recently been received from your network'

class BlacklistPolicy(GreylistPolicy):
    def __init__(self, manager):
        super(BlacklistPolicy, self).__init__(manager)
        self.soft_threshold = int(manager.getConfigItem(
            'blacklist', 'soft_threshold', 1))
        self.hard_threshold = int(manager.getConfigItem(
            'blacklist', 'hard_treshold', 3))
        self.classc_threshold = int(manager.getConfigItem(
            'blacklist', 'classc_threshold', 3))

    def loadGreylistClass(self):
        self.greylist_class = createGreylistClass(
            self.manager.getConfigItem('blacklist', 'interval', 720))

    def processRequest(self):
        ip_num, helo_num = self.getBlacklistThresholds()
        if ip_num >= helo_num:
            num = ip_num
            parameter = self.manager.get('client_address')
        else:
            num = helo_num
            parameter = self.manager.get('helo_name')

        rcpt_to, mail_from, ip_address = self.getGreylistTuple()
        if num >= self.hard_threshold:
            return HARD_REJECTED % parameter
        elif num >= self.soft_threshold:
            return self.greylist(rcpt_to, mail_from, ip_address,
                                 SOFT_REJECTED % parameter)
        elif self.getClasscSpamCount(ip_address) >= self.classc_threshold:
            return self.greylist(rcpt_to, mail_from, ip_address,
                                 CLASSC_REJECTED)
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
        query = self.manager.session.query(Spam)
        classc = '.'.join(ip_address.split('.')[0:3])
        classc = '%s.%%' % classc
        return query.filter(Spam.ip_address.like(classc)).count()
