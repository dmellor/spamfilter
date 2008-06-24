import re
import sys
import time
from ConfigParser import ConfigParser
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(autoflush=False, transactional=True)

class Policy(object):
    def __init__(self, config_file):
        self.values = {}
        self.config = ConfigParser()
        self.config.read(config_file)
        engine = create_engine(self.config.get('database', 'dburi'),
                               convert_unicode=False, echo=False)
        self.session = Session(bind=engine.connect())
        self.session.connection().execute(
            'set transaction isolation level serializable')

    def process(self):
        name_value = re.compile('^([^=]*)=(.*)')
        while True:
            line = sys.stdin.readline()
            if not line:
                break

            if line != '\n':
                match = name_value.search(line)
                name, value = match.groups()
                self.values[name] = value
            else:
                retries = 0
                num_retries = int(self.getConfigItem('general', 'retries', 2))
                while retries < num_retries:
                    action = None
                    err_status = None
                    try:
                        action = self.processRequest()
                        self.session.commit()
                        break
                    except Exception, exc:
                        self.session.rollback()
                        err_status = str(exc)
                        retries += 1
                        time.sleep(
                            int(self.getConfigItem('general', 'wait', 5)))

                if err_status:
                    err_status = re.sub('\n', '_', err_status)
                    sys.stdout.write('action=451 %s\n\n' % err_status)
                else:
                    sys.stdout.write('action=%s\n\n' % action)

                sys.stdout.flush()
                self.values = {}

    def processRequest(self):
        raise Exception('Implementation not found')

    def getConfigItem(self, section, name, default):
        try:
            return self.config.get(section, name)
        except:
            return default
