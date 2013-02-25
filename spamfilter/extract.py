import email
import base64
import quopri
import re

class EmailExtractor(object):
    def process(self, fp):
        self.original_message = ''.join(fp.readlines())
        self.processed = False
        self.processMessage(email.message_from_string(self.original_message))

    def processMessage(self, message):
        content_type = message.get_content_type()
        filename = message.get_filename()
        if content_type == 'message/rfc822' or (content_type == 'text/plain'
                                                and filename == 'spam.txt'):
            if content_type == 'message/rfc822':
                embedded = message.get_payload(0)
            else:
                embedded = message

            if message['Content-Transfer-Encoding'] == 'base64':
                self.original_message = base64.b64decode(embedded.get_payload())
                embedded = email.message_from_string(self.original_message)
            elif message['Content-Transfer-Encoding'] == 'quoted-printable':
                self.original_message = quopri.decodestring(
                    embedded.get_payload())
                embedded = email.message_from_string(self.original_message)
            else:
                # In order to extract the exact contents of the original message
                # we must search for the content within the MIME boundaries in
                # the file passed to the process method. The email.generator
                # package can change the format of the message when flattening
                # a message's payload, which will prevent a valid DKIM signature
                # for the embedded message from being verified.
                start = 0
                while self.index != 0:
                    start = self.original_message.index(self.boundary, start)
                    start += len(self.boundary) + 1
                    self.index -= 1

                # Advance the end index past the opening linefeed of the
                # boundary and extract the embedded message. The original
                # message can then be extracted by omitting the headers and
                # extracting the body content.
                end = self.original_message.index(self.boundary, start)
                rfc_message = self.original_message[start:end + 1]
                lines = rfc_message.split('\n')
                regexp = re.compile(r'^\s*$')
                start = 0
                while True:
                    if regexp.search(lines[start]):
                        break

                    start += 1

                self.original_message = '\n'.join(lines[start + 1:])

            self.actOnMessage(embedded)
            self.processed = True
        elif 'attachment' in (message['Content-Disposition'] or ''):
            self.original_message = message.get_payload()
            self.actOnMessage(email.message_from_string(self.original_message))
            self.processed = True
        else:
            payload = message.get_payload()
            if isinstance(payload, list):
                self.boundary = '\n--' + message.get_boundary()
                self.index = 1
                for p in payload:
                    if not self.processed:
                        self.processMessage(p)
                        self.index += 1

    def actOnMessage(self, message):
        raise Exception('Implementation not found')
