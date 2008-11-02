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
        self.greylist_class = greylist.createGreylistClass(
            self.getConfigItem('greylist', 'interval', 30))

    def processRequestInSession(self, session):
        ip_address = self.values.get('client_address')
        rcpt_to = self.values.get('recipient')
        mail_from = self.values.get('sender') or None
        threshold = int(self.getConfigItem('greylist', 'auto_threshold', 3))
        if isGreylisted(session, ip_address, rcpt_to, mail_from,
                        self.greylist_class, threshold):
            return REJECTED
        else:
            return ACCEPTED


def isGreylisted(session, ip_address, rcpt_to, mail_from, greylist_class,
                 threshold=None):
    ip_address = '.'.join(ip_address.split('.')[:3])
    rcpt_to = rcpt_to.lower()
    if mail_from:
        mail_from = mail_from.lower()

    # Check if the tuple has been seen before.
    query = session.query(greylist_class)
    query = query.filter_by(ip_address=ip_address, mail_from=mail_from,
                            rcpt_to=rcpt_to)
    record = query.first()

    # Detemine the status and update the greylist record.
    if record and record.accepted:
        record.successful += 1
        return False
    elif record:
        record.unsuccessful += 1
        return True
    else:
        record = greylist_class()
        record.ip_address = ip_address
        record.mail_from = mail_from
        record.rcpt_to = rcpt_to
        record.unsuccessful = 1
        session.save(record)
        return True
