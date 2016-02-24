from spamfilter.model.greylist import create_greylist_class
from spamfilter.model.sentmail import SentMail
from spamfilter.policy import Policy, ACCEPTED
from spamfilter.mixin import query_postfix_db

REJECTED = \
    'defer_if_permit System temporarily unavailable, please try again later'
HARD_REJECTED = 'reject '


class GreylistPolicy(Policy):
    def __init__(self, manager):
        super(GreylistPolicy, self).__init__(manager)
        self.load_greylist_class()

    # noinspection PyAttributeOutsideInit
    def load_greylist_class(self):
        self.greylist_class = create_greylist_class(
            self.manager.get_config_item('greylist', 'interval', 30))

    def process_request(self):
        # Determine the greylist tuple, and check if the recipient should be
        # subjected to the greylist policy.
        rcpt_to, mail_from, ip_address = self.get_greylist_tuple()
        nogreylist_db = self.manager.get_config_item('greylist',
                                                     'nogreylist_db', None)
        if nogreylist_db and query_postfix_db(nogreylist_db, rcpt_to):
            status = ACCEPTED
        else:
            status = REJECTED

        return self.greylist(rcpt_to, mail_from, ip_address, status)

    def greylist(self, rcpt_to, mail_from, ip_address, status):
        instance = self.manager.get('instance')
        record = self.get_greylist_record(rcpt_to, mail_from, ip_address)
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
                    self.is_accepted(mail_from, rcpt_to)):
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
        if self.is_accepted(mail_from, rcpt_to):
            status = ACCEPTED

        if not status.startswith(HARD_REJECTED):
            self.create_greylist_record(rcpt_to, mail_from, ip_address,
                                        instance, status)

        return status

    def get_greylist_record(self, rcpt_to, mail_from, ip_address):
        # Load the record - this will be null if the tuple has not been seen
        # before.
        classc = '.'.join(ip_address.split('.')[:3])
        query = self.manager.session.query(self.greylist_class)
        query = query.filter_by(ip_address=classc, mail_from=mail_from,
                                rcpt_to=rcpt_to)
        return query.first()

    def get_greylist_tuple(self):
        rcpt_to = self.manager.get('recipient').lower()
        mail_from = self.manager.get('sender') or None
        if mail_from:
            mail_from = mail_from.lower()

        ip_address = self.manager.get('client_address')
        return rcpt_to, mail_from, ip_address

    def create_greylist_record(self, rcpt_to, mail_from, ip_address, instance,
                               status):
        classc = '.'.join(ip_address.split('.')[:3])
        record = self.greylist_class(ip_address=classc, rcpt_to=rcpt_to,
                                     mail_from=mail_from,
                                     last_instance=instance)
        if status == ACCEPTED:
            record.successful = 1
        else:
            record.unsuccessful = 1

        self.manager.session.add(record)

    def is_whitelisted(self, mail_from):
        if not mail_from:
            return False

        whitelist_db = self.manager.get_config_item('greylist', 'whitelist_db',
                                                    None)
        if not whitelist_db:
            return False

        if query_postfix_db(whitelist_db, mail_from):
            return True
        else:
            domain = mail_from[mail_from.index('@') + 1:]
            return query_postfix_db(whitelist_db, domain)

    def is_known_correspondent(self, mail_from, recipient):
        query = self.manager.session.query(SentMail)
        return query.filter_by(sender=recipient, recipient=mail_from).count()

    def is_accepted(self, mail_from, rcpt_to):
        return (self.is_whitelisted(mail_from) or
                self.is_known_correspondent(mail_from, rcpt_to))
