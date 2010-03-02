import sys
import email
import base64
import quopri

class EmailExtractor(object):
    def process(self, fp=sys.stdin):
        message = email.message_from_file(fp)
        self.processMessage(message)

    def processMessage(self, message):
        if message.get_content_type() == 'message/rfc822':
            embedded = message.get_payload(0)
            if message['Content-Transfer-Encoding'] == 'base64':
                embedded = email.message_from_string(
                    base64.b64decode(embedded.get_payload()))
            elif message['Content-Transfer-Encoding'] == 'quoted-printable':
                embedded = email.message_from_string(
                    quopri.decodestring(embedded.get_payload()))

            self.actOnMessage(embedded)
        elif 'attachment' in (message['Content-Disposition'] or ''):
            self.actOnMessage(email.message_from_string(message.get_payload()))
        else:
            payload = message.get_payload()
            if isinstance(payload, list):
                for p in payload:
                    self.processMessage(p)

    def actOnMessage(self, message):
        raise Exception('Implementation not found')
