"""Defines the greylist table. """

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

greylist_table = Table(
    'greylist', meta,
    Column('id', Integer, Sequence('greylist_id_seq'), primary_key=True),
    Column('ip_address', String(15), nullable=False),
    Column('mail_from', String(1024), nullable=True),
    Column('rcpt_to', String(1024), nullable=False),
    Column('created', TIMESTAMP, PassiveDefault(text('now()'))),
    Column('modified', TIMESTAMP),
    Column('successful', Integer, PassiveDefault('0'), nullable=False),
    Column('unsuccessful', Integer, PassiveDefault('0'), nullable=False),
    UniqueConstraint('ip_address', 'mail_from', 'rcpt_to',
                     name='greylist_tuple'))

def greylist(interval=None):

    class Greylist(object):
        pass

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

__all__ = ['greylist', 'greylist_table']
