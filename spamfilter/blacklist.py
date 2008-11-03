from spamfilter.policy import Policy
from spamfilter.model.spam import Spam
from spamfilter.model.greylist import createGreylistClass
from spamfilter.model.blacklist import Blacklist
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
        ip_address = self.values.get('client_address')
        query = session.query(Spam)
        num = query.filter_by(ip_address=ip_address).count()
        if num >= self.hard_threshold:
            session.save(Blacklist(ip_address=ip_address))
            return HARD_REJECTED % ip_address
        elif num >= self.soft_threshold:
            rcpt_to = self.values.get('recipient')
            mail_from = self.values.get('sender') or None
            if isGreylisted(session, ip_address, rcpt_to, mail_from,
                            self.greylist_class):
                session.save(Blacklist(ip_address=ip_address))
                return SOFT_REJECTED % ip_address
            else:
                return ACCEPTED
        else:
            helo = self.values.get('helo_name')
            num = query.filter_by(helo=helo).count()
            if num >= self.soft_threshold:
                rcpt_to = self.values.get('recipient')
                mail_from = self.values.get('sender') or None
                if isGreylisted(session, ip_address, rcpt_to, mail_from,
                                self.greylist_class):
                    session.save(Blacklist(ip_address=ip_address))
                    return SOFT_REJECTED % helo
                else:
                    return ACCEPTED
            else:
                return ACCEPTED
