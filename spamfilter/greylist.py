import sys
import re
from sqlalchemy import *
import spamfilter.model.greylist as greylist
from spamfilter.policy import Policy

ACCEPTED = 'dunno'
REJECTED = \
    'defer_if_permit System temporarily unavailable, please try again later'

class GreylistPolicy(Policy):
    def __init__(self, **kws):
        super(GreylistPolicy, self).__init__(**kws)
        self.Greylist = greylist.createGreylistClass(
            self.getConfigItem('greylist', 'interval', 30))

    def processRequestInSession(self, session):
        ip_address = self.values.get('client_address')
        ip_address = '.'.join(ip_address.split('.')[:3])
        rcpt_to = self.values.get('recipient').lower()
        mail_from = self.values.get('sender') or None
        if mail_from:
            mail_from = mail_from.lower()
        
        # Check if the tuple has been seen before.
        query = session.query(self.Greylist)
        query = query.filter_by(ip_address=ip_address, mail_from=mail_from,
                                rcpt_to=rcpt_to)
        record = query.first()

        # If the number of successful connections from a domain has been
        # achieved, then we automatically accept the connection.
        auto_accept = False
        if not record or not record.accepted:
            threshold = self.getConfigItem('greylist', 'auto_threshold', 3)
            threshold = int(threshold)
            if threshold and mail_from:
                match = re.compile('(@.*)$').search(mail_from)
                if match:
                    table = greylist.greylist_table
                    query = select([func.sum(table.c.successful)])
                    query = query.where(and_(
                        table.c.ip_address == bindparam('ip_address'),
                        table.c.rcpt_to == bindparam('rcpt_to'),
                        table.c.mail_from.like(bindparam('domain'))))
                    result = session.connection().execute(
                        query, ip_address=ip_address, rcpt_to=rcpt_to,
                        domain='%' + match.group(1)).fetchone()
                    if result[0]:
                        auto_accept = result[0] >= threshold

        # Detemine the status and update the greylist record.
        if record and (record.accepted or auto_accept):
            record.successful += 1
            return ACCEPTED
        elif record:
            record.unsuccessful += 1
            return REJECTED
        elif auto_accept:
            record = self.Greylist()
            record.ip_address = ip_address
            record.mail_from = mail_from
            record.rcpt_to = rcpt_to
            record.successful = 1
            session.save(record)
            return ACCEPTED
        else:
            record = self.Greylist()
            record.ip_address = ip_address
            record.mail_from = mail_from
            record.rcpt_to = rcpt_to
            record.unsuccessful = 1
            session.save(record)
            return REJECTED
