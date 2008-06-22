import re
import sys
import time
from ConfigParser import ConfigParser
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from model.greylist import *

Session = sessionmaker(autoflush=False, transactional=True)
Greylist = None

ACCEPTED = "dunno"
REJECTED = \
    "defer_if_permit System temporarily unavailable, please try again later"

def main():
    global Greylist
    config = ConfigParser()
    config.read('config.ini')
    engine = create_engine(config.get('database', 'dburi'),
                           convert_unicode=False, echo=False)
    session = Session(bind=engine.connect())
    session.connection().execute(
        'set transaction isolation level serializable')
    Greylist = greylist(config.get('greylist', 'interval'))

    name_value = re.compile('^([^=]*)=(.*)')
    ip = None
    mail_from = None
    rcpt_to = None
    while True:
        line = sys.stdin.readline()
        if not line:
            break

        if line != '\n':
            match = name_value.search(line)
            name, value = match.groups()
            if name == 'client_address':
                ip = '.'.join(value.split('.')[:3])
            elif name == 'sender':
                mail_from = value.lower()
            elif name == 'recipient':
                rcpt_to = value.lower()
        else:
            retries = 0
            while retries < 2:
                action = None
                err_status = None
                try:
                    action = process(session, config, ip, mail_from, rcpt_to)
                    session.commit()
                    break
                except Exception, exc:
                    session.rollback()
                    err_status = str(exc)
                    retries += 1
                    time.sleep(10)

            if err_status:
                err_status = re.sub('\n', '_', err_status)
                sys.stdout.write('action=451 %s\n\n' % err_status)
            else:
                sys.stdout.write('action=%s\n\n' % action)

            sys.stdout.flush()
            ip = None
            mail_from = None
            rcpt_to = None

def process(session, config, ip_address, mail_from, rcpt_to):
    # Check if the tuple has been seen before.
    query = session.query(Greylist).filter_by(ip_address=ip_address,
                                              mail_from=mail_from,
                                              rcpt_to=rcpt_to)
    record = query.first()

    # If the number of successful connections from a domain has been acheived,
    # then we accept the connection.
    auto_accept = False
    if not record:
        threshold = config.getint('greylist', 'auto_threshold')
        if threshold:
            match = re.compile('(@.*)$').search(mail_from)
            if match:
                query = select([func.sum(greylist_table.c.successful)])
                query = query.where(and_(
                    greylist_table.c.ip_address == bindparam('ip_address'),
                    greylist_table.c.rcpt_to == bindparam('rcpt_to'),
                    greylist_table.c.mail_from.like(bindparam('domain'))))
                result = session.connection().execute(
                    query, ip_address=ip_address, rcpt_to=rcpt_to,
                    domain='%' + match.group(1)).fetchone()
                if result[0]:
                    auto_accept = result[0] >= threshold

    # Detemine the status and update the greylist record.
    if record and record.accepted:
        record.successful += 1
        return ACCEPTED
    elif record:
        record.unsuccessful += 1
        return REJECTED
    elif auto_accept:
        record = Greylist()
        record.ip_address = ip_address
        record.mail_from = mail_from
        record.rcpt_to = rcpt_to
        record.successful = 1
        session.save(record)
        return ACCEPTED
    else:
        record = Greylist()
        record.ip_address = ip_address
        record.mail_from = mail_from
        record.rcpt_to = rcpt_to
        record.unsuccessful = 1
        session.save(record)
        return REJECTED

if __name__ == "__main__":
    main()
