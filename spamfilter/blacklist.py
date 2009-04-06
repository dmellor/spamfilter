from spamfilter.policy import Policy
from spamfilter.model.spam import Spam
from spamfilter.model.greylist import createGreylistClass
from spamfilter.greylist import isGreylisted
from spamfilter.mixin import createSession

ACCEPTED = 'dunno'
SOFT_REJECTED = 'defer_if_permit Spam has recently been received from %s'
HARD_REJECTED = 'reject Spam has recently been received from %s'

class BlacklistPolicy(Policy):
    def __init__(self, dbkeys, **kws):
        super(BlacklistPolicy, self).__init__(**kws)
        sessions = []
        for key in dbkeys:
            try:
                dburi = self.getConfigItem('database', key)
                sessions.append(createSession(dburi))
            except:
                # If a connection cannot be made to a database, then that
                # database is ignored.
                pass

        self.extra_sessions = sessions
        self.greylist_class = createGreylistClass(
            self.getConfigItem('blacklist', 'interval', 720))
        self.soft_threshold = int(self.getConfigItem('blacklist',
                                                     'soft_threshold', 1))
        self.hard_threshold = int(self.getConfigItem('blacklist',
                                                     'hard_treshold', 3))

    def processRequest(self):
        action, err_status = self.transaction(self.session)
        if err_status or action != ACCEPTED:
            return action, err_status

        for session in self.extra_sessions:
            action, err_status = self.transaction(session)
            if err_status or action != ACCEPTED:
                return action, err_status

        return action, err_status

    def processRequestInSession(self, session):
        ip_num, helo_num = getBlacklistThresholds(session, self.values)
        if ip_num >= helo_num:
            num = ip_num
            parameter = self.values.get('client_address')
        else:
            num = helo_num
            parameter = self.values.get('helo_name')

        if num >= self.hard_threshold:
            return HARD_REJECTED % parameter
        elif num >= self.soft_threshold:
            rcpt_to = self.values.get('recipient')
            mail_from = self.values.get('sender') or None
            ip_address = self.values.get('client_address')
            if isGreylisted(session, ip_address, rcpt_to, mail_from,
                            self.greylist_class):
                return SOFT_REJECTED % parameter
            else:
                return ACCEPTED
        else:
            return ACCEPTED

def getBlacklistThresholds(session, values):
    query = session.query(Spam)
    ip_address = values.get('client_address')
    ip_num = query.filter_by(ip_address=ip_address).count()
    helo = values.get('helo_name')
    helo_num = query.filter_by(helo=helo).count()

    return ip_num, helo_num
