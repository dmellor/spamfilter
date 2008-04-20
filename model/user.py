"""The definition of a user account."""

from sqlalchemy import *
from sqlalchemy.orm import *
from model import meta

class User(object):
    pass

users_table = Table(
    'users', meta,
    Column('id', Integer, Sequence('users_id_seq'), primary_key=True),
    Column('name', String(255), nullable=False))

class Address(object):
    pass

user_addresses_table = Table(
    'user_addresses', meta,
    Column('id', Integer, Sequence('user_addresses_id_seq'), primary_key=True),
    Column('address', String(255), unique=True, nullable=False),
    Column('user_id', Integer, ForeignKey('users.id'), nullable=False))

mapper(Address, user_addresses_table)

mapper(User, users_table,
       properties=dict(addresses=relation(Address, backref='user')))
