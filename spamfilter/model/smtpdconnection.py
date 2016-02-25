"""Defines the smtpd_connections table. """

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class SmtpdConnection(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


smtpd_connections_table = Table(
    'smtpd_connections', meta,
    Column('id', Integer, Sequence('smtpd_connections_id_seq'),
           primary_key=True),
    Column('ip_address', String(15), nullable=False),
    Column('classc', String(11), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False))

mapper(SmtpdConnection, smtpd_connections_table)

__all__ = ['SmtpdConnection', 'smtpd_connections_table']
