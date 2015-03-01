from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class SentMail(object):
    def __init__(self, messages=1, **kws):
        self.messages = messages
        for k, v in kws.items():
            setattr(self, k, v)


sent_mail_table = Table(
    'sent_mail', meta,
    Column('id', Integer, Sequence('sent_mail_id_seq'), primary_key=True),
    Column('sender', String(1024), nullable=False),
    Column('recipient', String(1024), nullable=False),
    Column('messages', Integer, nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False),
    Column('modified', TIMESTAMP, nullable=False))

mapper(SentMail, sent_mail_table)

__all__ = ['SentMail', 'sent_mail_table']
