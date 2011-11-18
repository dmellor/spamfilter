from spamfilter.model.greylist import createGreylistClass
from spamfilter.model.autowhitelist import AutoWhitelist
from spamfilter.model.sentmail import SentMail
from spamfilter.policy import Policy, ACCEPTED
from spamfilter.mixin import queryPostfixDB

REJECTED = \
    'defer_if_permit System temporarily unavailable, please try again later'
HARD_REJECTED = 'reject '

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
            status = ACCEPTED
        else:
            status = REJECTED

        return self.greylist(rcpt_to, mail_from, ip_address, status)

    def greylist(self, rcpt_to, mail_from, classc, status):
        classc = getClasscAddress(classc)
        instance = self.manager.get('instance')
        record = self.getGreylistRecord(rcpt_to, mail_from, classc)
        if record:
            if instance == record.last_instance:
                # First check if the current message instance has already been
                # processed by a previous GreylistPolicy, which will be the
                # case if the message was blacklisted. If so, then the
                # blacklist policy will have already determined the outcome for
                # this message and there is nothing further that needs to be
                # done here. This requires that the blacklist policy appear
                # before the greylist policy in the configuration file.
                return ACCEPTED
            elif ((record.accepted and not status.startswith(HARD_REJECTED)) or
                  self.isAccepted(mail_from, rcpt_to, classc)):
                record.last_instance = instance
                record.successful += 1
                return ACCEPTED
            else:
                record.last_instance = instance
                record.unsuccessful += 1
                return status

        # The connection has not been seen before - create a new greylist
        # record if the status is not a hard rejection and the address is not
        # whitelisted.
        if self.isAccepted(mail_from, rcpt_to, classc):
            status = ACCEPTED

        if not status.startswith(HARD_REJECTED):
            self.createGreylistRecord(rcpt_to, mail_from, classc, instance,
                                      status)

        return status

    def getGreylistRecord(self, rcpt_to, mail_from, classc):
        # Load the record - this will be null if the tuple has not been seen
        # before.
        query = self.manager.session.query(self.greylist_class)
        query = query.filter_by(ip_address=classc, mail_from=mail_from,
                                rcpt_to=rcpt_to)
        return query.first()

    def getGreylistTuple(self):
        rcpt_to = self.manager.get('recipient').lower()
        mail_from = self.manager.get('sender') or None
        if mail_from:
            mail_from = mail_from.lower()

        ip_address = self.manager.get('client_address')
        return rcpt_to, mail_from, ip_address

    def createGreylistRecord(self, rcpt_to, mail_from, classc, instance,
                             status):
        record = self.greylist_class(ip_address=classc, rcpt_to=rcpt_to,
                                     mail_from=mail_from,
                                     last_instance=instance)
        if status == ACCEPTED:
            record.successful = 1
        else:
            record.unsuccessful = 1

        self.manager.session.add(record)

    def isAutoWhitelisted(self, mail_from, classc):
        query = self.manager.session.query(AutoWhitelist)
        classb = '.'.join(classc.split('.')[:2])
        record = query.filter_by(email=mail_from, ip=classb).first()
        if record:
            threshold = int(self.manager.getConfigItem(
                'greylist', 'whitelist_threshold', 5))
            if record.totscore / record.count < threshold:
                return True

        return False

    def isWhitelisted(self, mail_from):
        if not mail_from:
            return False

        whitelist_db = self.manager.getConfigItem('greylist', 'whitelist_db',
                                                  None)
        if not whitelist_db:
            return False

        if queryPostfixDB(whitelist_db, mail_from):
            return True
        else:
            domain = mail_from[mail_from.index('@') + 1:]
            return queryPostfixDB(whitelist_db, domain)

    def isKnownCorrespondent(self, mail_from, recipient):
        query = self.manager.session.query(SentMail)
        return query.filter_by(sender=recipient, recipient=mail_from).count()

    def isAccepted(self, mail_from, rcpt_to, classc):
        return (self.isWhitelisted(mail_from) or
                self.isAutoWhitelisted(mail_from, classc) or
                self.isKnownCorrespondent(mail_from, rcpt_to))

def getClasscAddress(ip_address):
    return '.'.join(ip_address.split('.')[:3])
