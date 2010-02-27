from sqlalchemy import *
from sqlalchemy.orm import *
from spamfilter.model import meta

class Virus(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

viruses_table = Table(
    'viruses', meta,
    Column('id', Integer, Sequence('viruses_id_seq'), primary_key=True),
    Column('bounce', String(1024), nullable=True),
    Column('ip_address', String(15), nullable=False),
    Column('helo', String(1024), nullable=False),
    Column('contents', TEXT, nullable=False),
    Column('virus', TEXT, nullable=False),
    Column('created', TIMESTAMP, server_default=text('now()'), nullable=False))

class VirusRecipient(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)

virus_recipients_table = Table(
    'virus_recipients', meta,
    Column('id', Integer, Sequence('virus_recipients_id_seq'),
           primary_key=True),
    Column('recipient', String(1024), nullable=False),
    Column('virus_id', Integer, ForeignKey('viruses.id'), nullable=False),
    Column('delivery_id', String(32)),
    UniqueConstraint('delivery_id'))

mapper(VirusRecipient, virus_recipients_table)

mapper(Virus, viruses_table,
       properties={
           'recipients': relation(VirusRecipient, backref='virus'),
           'contents': deferred(viruses_table.c.contents),
           'subject': column_property(
                func.extract_header(text("'Subject'"),
                                    viruses_table.c.contents).label('subject'),
                deferred=True)
       })

__all__ = ['Virus', 'viruses_table', 'VirusRecipient',
           'virus_recipients_table']
