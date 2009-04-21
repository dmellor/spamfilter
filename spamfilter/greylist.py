from spamfilter.model.greylist import createGreylistClass
from spamfilter.policy import Policy, ACCEPTED
from spamfilter.mixin import queryPostfixDB

REJECTED = \
    'defer_if_permit System temporarily unavailable, please try again later'

class GreylistPolicy(Policy):
    def __init__(self, manager):
        super(GreylistPolicy, self).__init__(manager)
        self.loadGreylistClass()

    def loadGreylistClass(self):
        self.greylist_class = createGreylistClass(
            self.manager.getConfigItem('greylist', 'interval', 30))

    def processRequest(self):
        # Determine the greylist tuple, and check if the recipient should be
        # subjected to the greylist policy.
        rcpt_to, mail_from, ip_address = self.getGreylistTuple()
        nogreylist_db = self.manager.getConfigItem('greylist', 'nogreylist_db',
                                                   None)
        if nogreylist_db and queryPostfixDB(nogreylist_db, rcpt_to):
            return ACCEPTED

        # First check if the current message instance has already been
        # processed by the blacklist policy, which will be the case if the
        # message was blacklisted. If so, then the blacklist policy will have
        # already determined the outcome for this message and there is nothing
        # further that needs to be done here. This requires that the blacklist
        # policy appear before the greylist policy in the configuration file.
        instance = self.manager.get('instance')
        record = self.getGreylistRecord(rcpt_to, mail_from, ip_address)
        if record:
            if instance == record.last_instance:
                # Message already handled by the blacklist policy
                return ACCEPTED
            elif record.accepted:
                record.last_instance = instance
                record.successful += 1
                return ACCEPTED
            else:
                record.last_instance = instance
                record.unsuccessful += 1
                return REJECTED
        else:
            self.createGreylistRecord(rcpt_to, mail_from, ip_address, instance)
            return REJECTED

    def getGreylistRecord(self, rcpt_to, mail_from, ip_address):
        # Load the record - this will be null if the tuple has not been seen
        # before.
        query = self.manager.session.query(self.greylist_class)
        query = query.filter_by(ip_address=ip_address, mail_from=mail_from,
                                rcpt_to=rcpt_to)
        return query.first()

    def getGreylistTuple(self):
        rcpt_to = self.manager.get('recipient').lower()
        mail_from = self.manager.get('sender') or None
        if mail_from:
            mail_from = mail_from.lower()

        ip_address = self.manager.get('client_address')
        ip_address = '.'.join(ip_address.split('.')[:3])

        return rcpt_to, mail_from, ip_address

    def createGreylistRecord(self, rcpt_to, mail_from, ip_address, instance):
        record = self.greylist_class()
        record.ip_address = ip_address
        record.mail_from = mail_from
        record.rcpt_to = rcpt_to
        record.last_instance = instance
        record.unsuccessful = 1
        self.manager.session.save(record)
