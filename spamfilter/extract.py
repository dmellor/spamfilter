import email
import base64
import quopri
import re
import sys


class EmailExtractor(object):
    # noinspection PyAttributeOutsideInit
    def process(self, fp):
        raw = re.sub(r'\r\n', '\n', ''.join(fp.readlines()))
        self.process_message(raw)

    # noinspection PyAttributeOutsideInit
    def process_message(self, raw):
        message = email.message_from_string(raw)
        disposition = message['Content-Disposition']
        if disposition and disposition.startswith('attachment'):
            contents = extract_contents(raw)
            if message['Content-Transfer-Encoding'] == 'base64':
                contents = base64.b64decode(contents)
            elif message['Content-Transfer-Encoding'] == 'quoted-printable':
                contents = quopri.decodestring(contents)

            self.act_on_message(email.message_from_string(contents))
            sys.exit(0)
        elif isinstance(message.get_payload(), list):
            num_parts = len(message.get_payload())
            boundary = '\n--' + message.get_boundary()
            offset = 0
            for i in range(num_parts):
                part, offset = extract_message(raw, boundary, offset)
                self.process_message(part)
        else:
            self.act_on_message(message)
            sys.exit(0)

    def act_on_message(self, message):
        raise Exception('Implementation not found')


def extract_message(message, boundary, offset):
    # In order to extract the exact contents of the original message
    # we must search for the content within the MIME boundaries in
    # the file passed to the process method. The email.generator
    # package can change the format of the message when flattening
    # a message's payload, which will prevent a valid DKIM signature
    # for the embedded message from being verified.
    start = message.index(boundary, offset)
    start += len(boundary) + 1

    # Advance the end index past the opening linefeed of the
    # boundary and extract the embedded message.
    end = message.index(boundary, start)
    rfc_message = message[start:end + 1]
    return rfc_message, end


def extract_contents(message):
    separator = message.index('\n\n')
    return message[separator + 2:]
