import re

from spamfilter.smtpproxy import SmtpProxy
from spamfilter.mixin import *


class Relay(SmtpProxy, ConfigMixin):
    """
    This class is used to relay mail from a backup MX server to the primary MX
    server. The primary MX server should enable XFORWARD and XCLIENT commands
    for the IP address of the backup MX server. This proxy translates the
    XFORWARD commands sent by the backup MX server into a single XCLIENT
    command. The purpose of this is to allow any policy delegation and sender
    access controls on the primary MX server to process the same client
    information as was seen by the backup MX server.
    """

    def __init__(self, config, **kws):
        super(Relay, self).__init__(**kws)
        self.read_config(config)
        self.xclient_command = ['XCLIENT']
        self.xclient_helo = None
        self.xclient_name = None

    def xforward(self, command):
        # Ensure that the remote_addr attribute is set.
        super(Relay, self).xforward(command)

        # Gather the attributes of the XFORWARD command, stripping out the
        # SOURCE attribute, as the XCLIENT command does not support it.
        source_index = -1
        regex = re.compile(r'\b(\S+)=(\S+)\b')
        for i in range(1, len(command)):
            name, value = regex.search(command[i]).groups()
            if name == 'SOURCE':
                source_index = i
            elif name == 'HELO':
                self.xclient_helo = value
            elif name == 'NAME':
                self.xclient_name = value

        if source_index != -1:
            del command[source_index]

        self.xclient_command.extend(command[1:])

    def data(self, command):
        super(Relay, self).data(command)
        self.xclient_command = ['XCLIENT']
        self.xclient_helo = None
        self.xclient_name = None

    def send_command_and_response(self, command):
        # Because more than one XFORWARD command can be sent but only a single
        # XCLIENT command can be sent, the XCLIENT command is not sent until
        # the MAIL command is about to be sent, and therefore a synthesised
        # response is sent back to the client.
        if command[0] == 'XFORWARD':
            self.output.write('250 Ok\r\n')
            self.output.flush()
        elif command[0] == 'MAIL':
            # If the address is in the POP before SMTP table then we do not
            # send the synthesised XCLIENT and HELO commands, which means that
            # the message will be treated for access check purposes as if it
            # originated from this host. Otherwise, if there is a remote client
            # name then the message was not injected onto the queue locally,
            # in which case we send the XCLIENT command, discard the response
            # and then send the synthesised HELO command and discard its
            # response before issuing the mail command.
            name = None
            send_commands = True
            pop_db = self.get_config_item('spamfilter', 'pop_db', None)
            if pop_db and query_postfix_db(pop_db, self.remote_addr):
                send_commands = False
            else:
                name = self.xclient_helo or self.xclient_name
                if not name:
                    send_commands = False

            if send_commands:
                self.command(self.xclient_command)
                self.send_response(discard=True)
                self.command(['HELO', name])
                self.send_response(discard=True)

            super(Relay, self).send_command_and_response(command)
        else:
            super(Relay, self).send_command_and_response(command)
