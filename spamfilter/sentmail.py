from spamfilter.model.sentmail import SentMail
from spamfilter.policy import Policy, ACCEPTED
from spamfilter.mixin import query_postfix_db, is_login


class SentMailPolicy(Policy):
    def __init__(self, manager):
        super(SentMailPolicy, self).__init__(manager)
        self.trusted_ips = manager.get_config_item_list('sent_mail',
                                                        'trusted_ips')

    def process_request(self):
        ip = self.manager.get('client_address')
        accepted = ip in self.trusted_ips
        if not accepted:
            accepted = is_login(self.manager.session, ip)

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
