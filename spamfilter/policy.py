import re
import sys
import time
from spamfilter.mixin import ConfigMixin, SessionMixin

class Policy(ConfigMixin, SessionMixin):
    def __init__(self, config):
        self.values = {}
        self.readConfig(config)
        self.createSession(self.getConfigItem('database', 'dburi'))

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
                        self.session.clear()
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
