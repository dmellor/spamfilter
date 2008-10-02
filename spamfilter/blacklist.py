from spamfilter.policy import Policy
from spamfilter.model.spam import Spam
from spamfilter.mixin import createSession

ACCEPTED = 'dunno'
REJECTED = 'reject Spam has recently been received from %s'

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
        ip_address = self.values.get('client_address')
        threshold = int(self.getConfigItem('blacklist', 'threshold', 1))
        query = session.query(Spam)
        num = query.filter_by(ip_address=ip_address).count()
        if num >= threshold:
            return REJECTED % ip_address
        else:
            return ACCEPTED
