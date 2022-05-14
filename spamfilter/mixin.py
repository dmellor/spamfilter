import codecs
import re
from email.header import decode_header
from subprocess import *
from spamfilter.model.srs import Srs

Session = None


class ConfigMixin(object):
    # noinspection PyAttributeOutsideInit
    def read_config(self, config_file):
        from ConfigParser import ConfigParser

        self.config = ConfigParser()
        self.config.read(config_file)

    def get_config_item(self, *args):
        section, name = args[:2]
        try:
            return self.config.get(section, name)
        except:
            if len(args) != 2:
                return args[2]
            else:
                raise

    def get_config_item_list(self, section, name):
        item = self.get_config_item(section, name, [])
        if type(item) is str:
            item = [x.strip() for x in item.split(',')]

        return item


def create_session(dburi, serializable=True):
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


def query_postfix_db(db, item):
    if item:
        postmap = Popen(['/usr/sbin/postmap', '-q', item, db], stdout=PIPE)
        line = postmap.stdout.readline()
        postmap.wait()
        return line.lower().startswith('ok')
    else:
        return False


def get_received_ips_and_helo(message, host):
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

                # Find all the IP addresses on the received line.
                for match in re.finditer(
                        r'\D(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\D', line):
                    ips.append(match.group(1))

    return ips, helo


def get_dkim_domain(message_object, original_message):
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


def is_dkim_verified(original_message):
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


def extract_original_address(address, domain, session):
    address_domain = address.split('@')[1]
    if address_domain == domain:
        digest = address.split('=')[1]
        query = session.query(Srs).filter_by(hash=digest)
        srs = query.first()
        if not srs:
            return None
        else:
            return srs.bounce
    else:
        return None


class MessageSummary(object):
    def __init__(self, **kws):
        for k, v in kws.items():
            setattr(self, k, v)


# This function tries to convert the text to Unicode. If that fails, then an
# ascii-encoded string will be returned.
def translate(txt):
    txt = _translate(txt)

    # Some email headers are incorrectly encoded. If the text was not encoded
    # according to RFC 2047, then we attempt to decode it to Unicode assuming
    # that the encoding is utf8. If that fails then we convert the text to
    # ascii encoding by deleting all non-ascii characters from the text.
    if not isinstance(txt, unicode):
        try:
            txt = txt.decode('utf8')
        except:
            txt = ''.join([x for x in txt if ord(x) < 128])

    return txt


# Transform the text according to RFC 2047.
def _translate(txt):
    if txt:
        try:
            chunks = decode_header(txt)
            translated = []
            for chunk in chunks:
                if chunk[1]:
                    translated.append(codecs.getdecoder(chunk[1])(chunk[0])[0])
                else:
                    translated.append(unicode(chunk[0]))

            return u''.join(translated)
        except:
            return txt
    else:
        # If the text was None, it is converted to an empty string in order to
        # prevent 'NoneType' object is not iterable when the return value of
        # this function is treated as a string.
        return '' if txt is None else txt


def get_body_type_charset(message, force_html=False):
    if force_html:
        allowed_types = ['text/html']
    else:
        allowed_types = ['text/plain', 'text/html']

    return _get_body_type_charset(message, allowed_types)


def _get_body_type_charset(message, allowed_types):
    payload = message.get_payload()
    content_type = message.get_content_type()
    charset = message.get_param('charset')
    body = None
    if not isinstance(payload, list):
        if content_type in allowed_types:
            body = payload
            transfer_encoding = message.get('Content-Transfer-Encoding', '')
            transfer_encoding = transfer_encoding.lower()
            if transfer_encoding == 'quoted-printable':
                import quopri
                body = quopri.decodestring(body)
            elif transfer_encoding == 'base64':
                import base64
                body = base64.b64decode(body)
    else:
        for msg in payload:
            body, content_type, charset = _get_body_type_charset(msg,
                                                                 allowed_types)
            if body:
                break

    return body, content_type, charset


__all__ = ['ConfigMixin', 'create_session', 'get_dkim_domain',
           'get_received_ips_and_helo', 'is_dkim_verified', 'query_postfix_db',
           'Session', 'extract_original_address', 'MessageSummary',
           'translate', 'get_body_type_charset']
