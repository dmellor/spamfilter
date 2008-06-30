from ConfigParser import ConfigParser
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class ConfigMixin(object):
    def readConfig(self, config_file):
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

Session = sessionmaker(autoflush=False, transactional=True)

class SessionMixin(object):
    def createSession(self, dburi):
        engine = create_engine(dburi, convert_unicode=False, echo=False)
        self.session = Session(bind=engine.connect())
        self.session.connection().execute(
            'set transaction isolation level serializable')
