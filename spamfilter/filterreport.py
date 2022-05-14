import os
import email
import smtplib

from spamfilter.mixin import ConfigMixin, create_session, MessageSummary
from spamfilter.mixin import translate, get_body_type_charset
from spamfilter.model.filtered import Filtered
from mako.template import Template
from cgi import escape


class FilterReportGenerator(ConfigMixin):
    def __init__(self, config):
        self.read_config(config)
        self.session = create_session(self.get_config_item('database', 'dburi'))
        self.template = Template(
            filename=os.path.join(os.path.dirname(__file__),
                                  'filterreport.html'),
            input_encoding='utf-8', output_encoding='utf-8')

    def list_messages(self):
        query = self.session.query(Filtered)
        filtered = query.all()
        filtered.sort(key=lambda y: y.id, reverse=True)
        remove_quoted_sender(filtered)
        messages = [MessageSummary(sender=escape(x.sender),
                                   subject=escape(translate(x.subject)),
                                   date=x.created.replace(microsecond=0),
                                   id=x.id)
                    for x in filtered]
        url = os.getenv('REQUEST_URI')
        index = url.rindex('/')
        page = self.template.render(
            server_name=os.getenv('SERVER_NAME'), filtered=messages,
            url_prefix=url[:index])
        print 'Content-Type: text/html; charset=utf-8'
        print
        print page

    def view_message(self):
        msg_id = os.getenv('PATH_INFO')[1:]
        query = self.session.query(Filtered).filter_by(id=msg_id)
        filtered = query.first()
        body, content_type = extract_body_content_type(filtered.contents)

        print 'Content-Type: text/html; charset=utf-8'
        print
        if content_type == 'text/html':
            print body
        else:
            print '<html><body><code>'
            print body
            print '</code></body></html>'

    def deliver_message(self):
        try:
            self._deliver_message()
            self.session.commit()
        except:
            self.session.rollback()
            raise

    def _deliver_message(self):
        msg_id = os.getenv('PATH_INFO')[1:]
        query = self.session.query(Filtered).filter_by(id=msg_id)
        filtered = query.first()

        # As the message was delivered via the Postfix local agent it will have
        # a From line at the beginning, which is not formatted as an email
        # header. We therefore remove it before delivering the message again.
        contents = filtered.contents
        if contents.startswith('From '):
            index = contents.index('\n')
            contents = contents[index + 1:]

        mail_server = smtplib.SMTP('localhost')
        mail_server.sendmail(filtered.sender, filtered.recipient, contents,
                             ['BODY=8BITMIME'])
        mail_server.quit()
        self.session.delete(filtered)

        url = os.getenv('REQUEST_URI')
        url = url[:-len(os.getenv('PATH_INFO'))]
        index = url.rindex('/')
        print 'Refresh: 0; url=%s/listfiltered' % url[:index]
        print 'Content-Type: text/html'
        print


def remove_quoted_sender(messages):
    for msg in messages:
        if msg.sender.startswith('"=?'):
            index = msg.sender.rindex('?="')
            quoted_name = msg.sender[1:index + 2]
            real_name = msg.sender[index + 3:]
            msg.sender = u'"%s"%s' % (translate(quoted_name),
                                      translate(real_name))
        elif msg.sender.startswith('=?'):
            index = msg.sender.rindex('?=')
            quoted_name = msg.sender[:index + 2]
            real_name = msg.sender[index + 2:]
            msg.sender = translate(quoted_name) + translate(real_name)


def extract_body_content_type(contents):
    message = email.message_from_string(contents)
    body, content_type, charset = get_body_type_charset(message,
                                                        force_html=True)
    if not body:
        body, content_type, charset = get_body_type_charset(message)

    if charset:
        try:
            body = body.decode(charset).encode('utf8')
        except UnicodeDecodeError:
            # Use the unmodified body if an error occurs.
            pass

    return body, content_type
