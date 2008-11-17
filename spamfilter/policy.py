import re
import sys
import time
import logging
from spamfilter.mixin import ConfigMixin, createSession

class Policy(ConfigMixin):
    def __init__(self, config):
        self.values = {}
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))

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
                action, err_status = self.processRequest()
                if err_status:
                    err_status = re.sub('\n', '_', err_status)
                    sys.stdout.write('action=451 %s\n\n' % err_status)
                else:
                    sys.stdout.write('action=%s\n\n' % action)

                sys.stdout.flush()
                self.values = {}

    def processRequest(self):
        return self.transaction(self.session)

    def transaction(self, session):
        retries = 0
        num_retries = int(self.getConfigItem('general', 'retries', 2))
        while retries < num_retries:
            action = None
            err_status = None
            try:
                action = self.processRequestInSession(session)
                session.commit()
                break
            except Exception, exc:
                session.rollback()
                session.clear()
                err_status = str(exc)
                logging.info('policy failed: %s', err_status)
                retries += 1
                wait_time = int(self.getConfigItem('general', 'wait', 5))
                logging.info('sleeping for %s seconds', wait_time)
                time.sleep(wait_time)

        return action, err_status

    def processRequestInSession(self, session):
        raise Exception('Implementation not found')
