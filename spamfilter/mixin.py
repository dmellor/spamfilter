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


class SessionMixin(object):
    Session = None
    
    def createSession(self, dburi):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        if not self.Session:
            self.Session = sessionmaker(autoflush=False, transactional=True)

        engine = create_engine(dburi, convert_unicode=False, echo=False)
        self.session = self.Session(bind=engine.connect())
        self.session.connection().execute(
            'set transaction isolation level serializable')


def queryPostfixDB(db, item):
    from subprocess import Popen, PIPE
    postmap = Popen(['/usr/sbin/postmap', '-q', item, db], stdout=PIPE)
    line = postmap.stdout.readline()
    postmap.wait()
    return line.startswith('ok')
