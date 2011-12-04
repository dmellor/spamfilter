from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

class ReceivedMail(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

received_mail_table = Table(
    'received_mail', meta,
    Column('id', Integer, Sequence('received_mail_id_seq'), primary_key=True),
    Column('email', String(1024), nullable=False),
    Column('ip_address', String(15), nullable=False),
    Column('is_spam', Boolean, nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False))

mapper(ReceivedMail, received_mail_table)

__all__ = ['ReceivedMail', 'received_mail_table']
