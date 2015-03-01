import re
import sys
import time
import logging
from spamfilter.mixin import ConfigMixin, create_session

ACCEPTED = 'dunno'


class PolicyManager(ConfigMixin):
    def __init__(self, config):
        self.values = {}
        self.read_config(config)
        self.session = create_session(self.get_config_item('database', 'dburi'))
        self.load_policies()

    # noinspection PyAttributeOutsideInit
    def load_policies(self):
        self.policies = []
        num = 0
        while True:
            num += 1
            class_name = self.get_config_item('policies', 'policy%s' % num,
                                              None)
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
                action, err_status = self.determine_action()
                if err_status:
                    err_status = re.sub('\n', '_', err_status)
                    sys.stdout.write('action=451 %s\n\n' % err_status)
                else:
                    sys.stdout.write('action=%s\n\n' % action)

                sys.stdout.flush()
                self.values = {}

    def determine_action(self):
        action = err_status = None
        retries = 0
        num_retries = int(self.get_config_item('general', 'retries', 2))
        while retries < num_retries:
            action = ACCEPTED
            err_status = None
            try:
                for policy in self.policies:
                    action = policy.process_request()
                    if action != ACCEPTED:
                        break

                self.session.commit()
                break
            except Exception, exc:
                self.session.rollback()
                err_status = str(exc)
                logging.info('policy failed: %s', err_status)
                retries += 1
                wait_time = int(self.get_config_item('general', 'wait', 5))
                logging.info('sleeping for %s seconds', wait_time)
                time.sleep(wait_time)

        return action, err_status


class Policy(object):
    def __init__(self, manager):
        self.manager = manager

    def process_request(self):
        raise Exception('Implementation not found')
