import re

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from spamfilter.model.auto_whitelist import AutoWhitelist
from spamfilter.model.greylist import create_greylist_class

Greylist = create_greylist_class()

def filter(from_session, to_session, cls, func, *unique_fields):
    from_query = from_session.query(cls)
    for record in from_query.all():
        to_query = to_session.query(cls)
        for field in unique_fields:
            to_query = to_query.filter(
                getattr(cls, field) == getattr(record, field))

        if to_query.count() == 0:
            func(record)

def escape(text):
    if text is None:
        text = r'\N'
    elif isinstance(text, str):
        text = re.sub(r'\n', '\\n', text)
        text = re.sub(r'\t', '\\t', text)
        text = re.sub(r'\r', '\\r', text)
    else:
        text = str(text)

    return text

def copy_auto_whitelist(from_session, to_session):
    print 'drop trigger auto_whitelist_stamp on auto_whitelist;'
    print 'copy auto_whitelist(username, email, ip, count, totscore, created, modified) from stdin;'

    def printRecord(record):
        print '\t'.join(escape(x) for x in [record.username, record.email,
                                            record.ip, record.count,
                                            record.totscore, record.created,
                                            record.modified])

    filter(from_session, to_session, AutoWhitelist, printRecord,
           'username', 'email', 'ip')
    print '\\.'
    print 'create trigger auto_whitelist_stamp before insert or update on auto_whitelist for each row execute procedure stamp();'

def copy_greylist(from_session, to_session):
    print 'drop trigger greylist_stamp on greylist;'
    print 'copy greylist(ip_address, mail_from, rcpt_to, created, modified, successful, unsuccessful) from stdin;'

    def printRecord(record):
        print '\t'.join(escape(x) for x in [record.ip_address,
                                            record.mail_from, record.rcpt_to,
                                            record.created, record.modified,
                                            record.successful,
                                            record.unsuccessful])

    filter(from_session, to_session, Greylist, printRecord,
           'ip_address', 'mail_from', 'rcpt_to')
    print '\.'
    print 'create trigger greylist_stamp before insert or update on greylist for each row execute procedure stamp();'

def main():
    Session = sessionmaker(autoflush=False, transactional=True)
    granite_engine = create_engine(
        'postgres://qmail:38hb75@granite/spamassassin', convert_unicode=False,
        echo=False)
    quartz_engine = create_engine(
        'postgres://qmail:38hb75@quartz/spamassassin', convert_unicode=False,
        echo=False)

    from_session = Session(bind=granite_engine.connect())
    from_session.connection().execute(
        'set transaction isolation level serializable')
    to_session = Session(bind=quartz_engine.connect())
    to_session.connection().execute(
        'set transaction isolation level serializable')
    try:
        copy_auto_whitelist(from_session, to_session)
        copy_greylist(from_session, to_session)
    finally:
        from_session.rollback()
        to_session.rollback()

if __name__ == '__main__':
    main()
