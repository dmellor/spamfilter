class ConfigMixin(object):
    def readConfig(self, config_file):
        from ConfigParser import ConfigParser
        self.config = ConfigParser()
        self.config.read(config_file)

    def getConfigItem(self, section, name, default=None):
        try:
            return self.config.get(section, name)
        except:
            if default is not None:
                return default
            else:
                raise


Session = None

def createSession(dburi):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    global Session
    if not Session:
        Session = sessionmaker(autoflush=False, transactional=True)

    engine = create_engine(dburi, convert_unicode=False, echo=False)
    session = Session(bind=engine.connect())
    session.connection().execute(
        'set transaction isolation level serializable')
    return session

def queryPostfixDB(db, item):
    if item:
        from subprocess import Popen, PIPE
        postmap = Popen(['/usr/sbin/postmap', '-q', item, db], stdout=PIPE)
        line = postmap.stdout.readline()
        postmap.wait()
        return line.startswith('ok')
    else:
        return False

def isGreylisted(session, ip_address, rcpt_to, mail_from, greylist_class,
                 threshold=None):
    ip_address = '.'.join(ip_address.split('.')[:3])
    rcpt_to = rcpt_to.lower()
    if mail_from:
        mail_from = mail_from.lower()

    # Check if the tuple has been seen before.
    query = session.query(greylist_class)
    query = query.filter_by(ip_address=ip_address, mail_from=mail_from,
                            rcpt_to=rcpt_to)
    record = query.first()

    # Detemine the status and update the greylist record.
    if record and record.accepted:
        record.successful += 1
        return False
    elif record:
        record.unsuccessful += 1
        return True
    else:
        record = greylist_class()
        record.ip_address = ip_address
        record.mail_from = mail_from
        record.rcpt_to = rcpt_to
        record.unsuccessful = 1
        session.save(record)
        return True
