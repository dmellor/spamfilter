"""Defines the login_failures table"""

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class LoginFailure(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


login_failures_table = Table(
    'login_failures', meta,
    Column('id', Integer, Sequence('login_failures_id_seq'), primary_key=True),
    Column('ip_address', String(40), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()')))

mapper(LoginFailure, login_failures_table)

__all__ = ['LoginFailure', 'login_failures_table']
