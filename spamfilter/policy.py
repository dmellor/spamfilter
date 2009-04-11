import re
import sys
import time
import logging
from spamfilter.mixin import ConfigMixin, createSession

class Policy(ConfigMixin):
    def __init__(self, config=None, policy=None):
        if policy:
            self.values = policy.values
            self.config = policy.config
            self.session = policy.session
        else:
            self.values = {}
            self.readConfig(config)
            self.session = createSession(
                self.getConfigItem('database', 'dburi'))

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
                action, err_status = self.determineAction()
                if err_status:
                    err_status = re.sub('\n', '_', err_status)
                    sys.stdout.write('action=451 %s\n\n' % err_status)
                else:
                    sys.stdout.write('action=%s\n\n' % action)

                sys.stdout.flush()
                self.values = {}

    def determineAction(self):
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
                logging.info('policy failed: %s', err_status)
                retries += 1
                wait_time = int(self.getConfigItem('general', 'wait', 5))
                logging.info('sleeping for %s seconds', wait_time)
                time.sleep(wait_time)

        return action, err_status

    def processRequest(self):
        raise Exception('Implementation not found')
