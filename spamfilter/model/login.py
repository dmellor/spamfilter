"""Defines the login table"""

from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta


class Login(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


login_table = Table(
    'login', meta,
    Column('id', Integer, Sequence('login_id_seq'), primary_key=True),
    Column('username', String(1024), nullable=False),
    Column('ip_address', String(40), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()')))

mapper(Login, login_table)

__all__ = ['Login', 'login_table']
