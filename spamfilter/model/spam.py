from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

class Spam(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

spam_table = Table(
    'spam', meta,
    Column('id', Integer, Sequence('spam_id_seq'), primary_key=True),
    Column('bounce', String(1024), nullable=True),
    Column('ip_address', String(15), nullable=False),
    Column('helo', String(1024), nullable=False),
    Column('contents', TEXT, nullable=False),
    Column('score', Float(precision='double'), nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False))

class SpamRecipient(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

spam_recipients_table = Table(
    'spam_recipients', meta,
    Column('id', Integer, Sequence('spam_recipients_id_seq'),
           primary_key=True),
    Column('recipient', String(1024), nullable=False),
    Column('spam_id', Integer, ForeignKey('spam.id'), nullable=False),
    Column('delivery_id', String(32)),
    UniqueConstraint('delivery_id'))

mapper(SpamRecipient, spam_recipients_table)

class SpamTest(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

spam_tests_table = Table(
    'spam_tests', meta,
    Column('id', Integer, Sequence('spam_tests_id_seq'), primary_key=True),
    Column('name', String(255), nullable=False),
    Column('description', TEXT, nullable=True),
    Column('score', Float(precision='double'), nullable=False),
    Column('spam_id', Integer, ForeignKey('spam.id'), nullable=False))

mapper(SpamTest, spam_tests_table)

mapper(Spam, spam_table,
       properties={
           'recipients': relation(SpamRecipient, backref='spam'),
           'contents': deferred(spam_table.c.contents),
           'subject': column_property(
               func.extract_header(text("'Subject'"),
                                   spam_table.c.contents).label('subject'),
               deferred=True),
           'tests': relation(SpamTest, backref='spam',
                             cascade='all, delete, delete-orphan')
       })

__all__ = ['Spam', 'spam_table', 'SpamRecipient', 'spam_recipients_table',
           'SpamTest', 'spam_tests_table']
