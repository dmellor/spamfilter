"""Defines the blacklist table."""

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

blacklist_table = Table(
    'blacklist', meta,
    Column('id', Integer, Sequence('blacklist_id_seq'), primary_key=True),
    Column('ip_address', String(15), nullable=False),
    Column('created', TIMESTAMP, PassiveDefault(text('now()'))))

class Blacklist(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

mapper(Blacklist, blacklist_table)

__all__ = ['Blacklist', 'blacklist_table']
