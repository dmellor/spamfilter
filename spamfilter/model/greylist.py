"""Defines the greylist table. """

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

greylist_table = Table(
    'greylist', meta,
    Column('id', Integer, Sequence('greylist_id_seq'), primary_key=True),
    Column('ip_address', String(11), nullable=False),
    Column('mail_from', String(1024), nullable=True),
    Column('rcpt_to', String(1024), nullable=False),
    Column('last_instance', String(255), nullable=True),
    Column('successful', Integer, server_default='0', nullable=False),
    Column('unsuccessful', Integer, server_default='0', nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()')),
    Column('modified', TIMESTAMP),
    UniqueConstraint('ip_address', 'mail_from', 'rcpt_to',
                     name='greylist_tuple'))

def createGreylistClass(interval=None):

    class Greylist(object):
        def __init__(self, **kws):
            for k, v in kws.items():
                setattr(self, k, v)

    if interval:
        mapper(Greylist, greylist_table, properties={
            'accepted': column_property(
                case(
                    value=text("now() - created > interval '%s minutes'"
                               % interval),
                    whens=[('true', 1)],
                    else_=0).label('accepted'))
            })
    else:
        mapper(Greylist, greylist_table)

    return Greylist

__all__ = ['createGreylistClass', 'greylist_table']
