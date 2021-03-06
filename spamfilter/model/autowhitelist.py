"""Defines the auto_whitelist table."""

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class AutoWhitelist(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


auto_whitelist_table = Table(
    'auto_whitelist', meta,
    Column('id', Integer, Sequence('auto_whitelist_id_seq'), primary_key=True),
    Column('username', String(1024), nullable=False),
    Column('email', String(1024), nullable=False),
    Column('ip', String(40), nullable=False),
    Column('count', Integer, nullable=False),
    Column('totscore', Float(precision='double'), nullable=False),
    Column('signedby', String(255), server_default=text(''), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()')),
    Column('modified', TIMESTAMP),
    UniqueConstraint('username', 'email', 'ip',
                     name='auto_whitelist_address-index'))

mapper(AutoWhitelist, auto_whitelist_table)

__all__ = ['AutoWhitelist', 'auto_whitelist_table']
