import sys
import re
from sqlalchemy import *
import spamfilter.model.greylist as greylist
from spamfilter.policy import Policy
from spamfilter.blacklist import BlacklistPolicy
from spamfilter.mixin import isGreylisted

ACCEPTED = 'dunno'
REJECTED = \
    'defer_if_permit System temporarily unavailable, please try again later'

class GreylistPolicy(Policy):
    def __init__(self, **kws):
        super(GreylistPolicy, self).__init__(**kws)
        self.greylist_class = greylist.createGreylistClass(
            self.getConfigItem('greylist', 'interval', 30))
        self.blacklist = BlacklistPolicy(policy=self)

    def processRequest(self):
        # First check if the current IP address is blacklisted. If it is, then
        # the blacklist policy will have already handled this message and there
        # is nothing further that needs to be done here. This is necessary
        # because Postfix still evalutes the recipient restrictions even if the
        # sender restrictions have already rejected the message.
        if max(self.blacklist.getBlacklistThresholds()) != 0:
            return ACCEPTED

        # Check if the current message should be greylisted.
        rcpt_to = self.values.get('recipient')
        mail_from = self.values.get('sender') or None
        ip_address = self.values.get('client_address')
        threshold = int(self.getConfigItem('greylist', 'auto_threshold', 3))
        if isGreylisted(self.session, ip_address, rcpt_to, mail_from,
                        self.greylist_class, threshold):
            return REJECTED
        else:
            return ACCEPTED
