import re
import sys
import time
import logging
from spamfilter.mixin import ConfigMixin, createSession

ACCEPTED = 'dunno'

class PolicyManager(ConfigMixin):
    def __init__(self, config):
        self.values = {}
        self.readConfig(config)
        self.session = createSession(self.getConfigItem('database', 'dburi'))
        self.loadPolicies()

    def loadPolicies(self):
        self.policies = []
        num = 0
        while True:
            num += 1
            class_name = self.getConfigItem('policies', 'policy%s' % num, None)
            if not class_name:
                break

            module, sep, klass = class_name.rpartition('.')
            klass = __import__(module)
            for component in class_name.split('.')[1:]:
                klass = getattr(klass, component)

            self.policies.append(klass(manager=self))

    def get(self, key):
        return self.values.get(key)

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
            action = ACCEPTED
            err_status = None
            try:
                for policy in self.policies:
                    action = policy.processRequest()
                    if action != ACCEPTED:
                        break

                self.session.commit()
                break
            except Exception, exc:
                self.session.rollback()
                err_status = str(exc)
                logging.info('policy failed: %s', err_status)
                retries += 1
                wait_time = int(self.getConfigItem('general', 'wait', 5))
                logging.info('sleeping for %s seconds', wait_time)
                time.sleep(wait_time)

        return action, err_status

class Policy(object):
    def __init__(self, manager):
        self.manager = manager

    def processRequest(self):
        raise Exception('Implementation not found')
