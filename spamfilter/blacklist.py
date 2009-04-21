from spamfilter.policy import ACCEPTED
from spamfilter.greylist import GreylistPolicy
from spamfilter.model.spam import Spam
from spamfilter.model.greylist import createGreylistClass

SOFT_REJECTED = 'defer_if_permit Spam has recently been received from %s'
HARD_REJECTED = 'reject Spam has recently been received from %s'

class BlacklistPolicy(GreylistPolicy):
    def __init__(self, manager):
        super(BlacklistPolicy, self).__init__(manager)
        self.soft_threshold = int(manager.getConfigItem('blacklist',
                                                        'soft_threshold', 1))
        self.hard_threshold = int(manager.getConfigItem('blacklist',
                                                        'hard_treshold', 3))
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

        if num >= self.hard_threshold:
            return HARD_REJECTED % parameter
        elif num >= self.soft_threshold:
            instance = self.manager.get('instance')
            rcpt_to, mail_from, ip_address = self.getGreylistTuple()
            record = self.getGreylistRecord(rcpt_to, mail_from, ip_address)
            if record:
                if instance == record.last_instance:
                    # Already handled by a previous policy.
                    return ACCEPTED
                elif record.accepted:
                    record.last_instance = instance
                    record.successful += 1
                    return ACCEPTED
                else:
                    record.last_instance = instance
                    record.unsuccessful += 1
                    return SOFT_REJECTED % parameter
            else:
                self.createGreylistRecord(rcpt_to, mail_from, ip_address,
                                          instance)
                return SOFT_REJECTED % parameter
        else:
            return ACCEPTED

    def getBlacklistThresholds(self):
        query = self.manager.session.query(Spam)
        ip_address = self.manager.get('client_address')
        ip_num = query.filter_by(ip_address=ip_address).count()
        helo = self.manager.get('helo_name')
        helo_num = query.filter_by(helo=helo).count()

        return ip_num, helo_num
