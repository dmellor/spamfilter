class ConfigMixin(object):
    def readConfig(self, config_file):
        from ConfigParser import ConfigParser
        self.config = ConfigParser()
        self.config.read(config_file)

    def getConfigItem(self, *args):
        section, name = args[0], args[1]
        try:
            return self.config.get(section, name)
        except:
            if len(args) != 2:
                return args[2]
            else:
                raise

Session = None

def createSession(dburi):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    global Session
    if not Session:
        Session = sessionmaker(autoflush=True, transactional=True)

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
