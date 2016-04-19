"""Defines the srs table."""

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

class Srs(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


srs_table = Table(
    'srs', meta,
    Column('id', Integer, Sequence('srs_id_seq'), primary_key=True),
    Column('hash', String(4), nullable=False),
    Column('bounce', String(1024), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False),
    UniqueConstraint('hash'))

mapper(Srs, srs_table)

__all__ = ['Srs', 'srs_table']
