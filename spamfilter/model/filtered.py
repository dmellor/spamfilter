from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class Filtered(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


filtered_table = Table(
    'filtered', meta,
    Column('id', Integer, Sequence('filtered_id_seq'), primary_key=True),
    Column('recipient', String(1024), nullable=False),
    Column('contents', TEXT, nullable=True),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False))

mapper(Filtered, filtered_table)

__all__ = ['Filtered', 'filtered_table']
