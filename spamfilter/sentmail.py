from spamfilter.model.sentmail import SentMail
from spamfilter.policy import Policy, ACCEPTED
from spamfilter.mixin import query_postfix_db


class SentMailPolicy(Policy):
    def __init__(self, manager):
        super(SentMailPolicy, self).__init__(manager)
        self.trusted_ips = manager.get_config_item_list('sent_mail',
                                                        'trusted_ips')
        self.pop_db = manager.get_config_item('spamfilter', 'pop_db', None)

    def process_request(self):
        ip = self.manager.get('client_address')
        accepted = ip in self.trusted_ips
        if not accepted and self.pop_db:
            accepted = query_postfix_db(self.pop_db, ip)

        if accepted:
            sender = self.manager.get('sender') or None
            if sender:
                sender = sender.lower()
                recipient = self.manager.get('recipient').lower()
                query = self.manager.session.query(SentMail)
                query = query.filter_by(sender=sender, recipient=recipient)
                record = query.first()
                if record:
                    record.messages += 1
                else:
                    record = SentMail(sender=sender, recipient=recipient)
                    self.manager.session.add(record)

        return ACCEPTED
