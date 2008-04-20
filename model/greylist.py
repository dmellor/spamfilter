"""Defines the greylist table. """

from sqlalchemy import *
from sqlalchemy.orm import *
from model import meta

class Greylist(object):
    pass

greylist_table = Table(
    'greylist', meta,
    Column('id', Integer, Sequence('greylist_id_seq'), primary_key=True),
    Column('ip_address', String(15), nullable=False),
    Column('mail_from', String(1024), nullable=False),
    Column('rcpt_to', String(1024), nullable=False),
    Column('created', TIMESTAMP, PassiveDefault(text('now()'))),
    Column('modified', TIMESTAMP),
    Column('successful', Integer, PassiveDefault('0'), nullable=False),
    Column('unsuccessful', Integer, PassiveDefault('0'), nullable=False),
    UniqueConstraint('ip_address', 'mail_from', 'rcpt_to',
                     name='gretylist_tuple'))

mapper(Greylist, greylist_table)
