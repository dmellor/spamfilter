import re
from subprocess import *

class ConfigMixin(object):
    def readConfig(self, config_file):
        from ConfigParser import ConfigParser
        self.config = ConfigParser()
        self.config.read(config_file)

    def getConfigItem(self, *args):
        section, name = args[:2]
        try:
            return self.config.get(section, name)
        except:
            if len(args) != 2:
                return args[2]
            else:
                raise

    def getConfigItemList(self, section, name):
        item = self.getConfigItem(section, name, [])
        if type(item) is str:
            item = [x.strip() for x in item.split(',')]

        return item

Session = None

def createSession(dburi, serializable=True):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    global Session
    if not Session:
        Session = sessionmaker()

    engine = create_engine(dburi, convert_unicode=False, echo=False)
    session = Session(bind=engine.connect())
    connection = session.connection()
    stmt = 'set session characteristics as transaction isolation level %s'
    mode = 'serializable' if serializable else 'read committed'
    connection.execute(stmt % mode)
    session.commit()
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

def getReceivedIPsAndHelo(message, host):
    received = message.get_all('Received')
    from_re = re.compile(r'^from\s+(\S+)')
    ips = []
    helo = None
    for line in received:
        match = from_re.search(line)
        if match:
            if match.group(1) == host:
                continue
            elif match.group(1) == 'localhost':
                continue
            else:
                if not helo:
                    helo = match.group(1)

                # Match the last IP address on the received line.
                match = re.search(r'\[([\d\.]+)\][^\[]*$', line)
                if match:
                    ips.append(match.group(1))

    return ips, helo

def getDKIMDomain(message_object, original_message):
    header1 = message_object.get_all('DKIM-Signature', [None])[0]
    header2 = message_object.get_all('DomainKey-Signature', [None])[0]
    if header1 and header2:
        flags = re.M | re.I
        match1 = re.search(r'^DKIM-Signature:', original_message, flags)
        match2 = re.search(r'^DomainKey-Signature:', original_message, flags)
        header = header1 if match1.start() < match2.start() else header2
    else:
        header = header1 or header2

    domain = ''
    if header:
        match = re.search(r'\bd=([^;\s]+)', header)
        if match:
            domain = match.group(1)

    return domain

def isDKIMVerified(original_message):
    # We use the Perl Mail::DKIM::Verifier package, as this is the same code
    # that is used by SpamAssassin. There is currently no adequate pure Python
    # solution for verifying DKIM signatures, as pydkim is buggy and sometimes
    # generates false negatives on validy signed messages.
    message = '\r\n'.join(original_message.split('\n'))
    process = Popen(
        ['perl', '-MMail::DKIM::Verifier', '-e',
         '$d = new Mail::DKIM::Verifier; $d->load(*STDIN); print $d->result;'],
        stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    process.stdin.write(message)
    process.stdin.close()
    result = process.stdout.readline()
    ret_code = process.wait()
    if ret_code != 0:
        raise Exception('DKIM verification failed: return code %s' % ret_code)

    return result == 'pass'
