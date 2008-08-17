import re

from spamfilter.smtpproxy import SmtpProxy

class Relay(SmtpProxy):
    """
    This class is used to relay mail from a backup MX server to the primary MX
    server. The primary MX server should enable XFORWARD and XCLIENT commands
    for the IP address of the backup MX server. This proxy translates the
    XFORWARD commands sent by the backup MX server into a single XCLIENT
    command. The purpose of this is to allow any policy delegation and sender
    access controls on the primary MX server to process the same client
    information as was seen by the backup MX server.
    """
    def __init__(self, **kws):
        super(Relay, self).__init__(**kws)
        self.xclient_command = ['XCLIENT']
        self.xclient_helo = None
        self.xclient_name = None

    def xforward(self, command):
        # Gather the attributes of the XFORWARD command, stripping out the
        # SOURCE attribute, as the XCLIENT command does not support it.
        source_index = -1
        regex = re.compile(r'\b(\S+)=(\S+)\b')
        for i in range(1, len(command)):
            name, value = regex.search(command[i]).groups()
            if name == 'SOURCE':
                source_index = i
            elif name == 'HELO':
                self.relay_helo = value
            elif name == 'NAME':
                self.relay_name = value

        if source_index != -1:
            del command[source_index]

        self.xclient_command.extend(command[1:])

    def data(self, command):
        super(Relay, self).data(command)
        self.xclient_command = ['XCLIENT']
        self.xclient_helo = None
        self.xclient_name = None

    def sendCommandAndResponse(self, command):
        # Because more than one XFORWARD command can be sent but only a single
        # XCLIENT command can be sent, the XCLIENT command is not sent until
        # the MAIL command is about to be sent, and synthesised responses are
        # sent back to the client.
        if command[0] == 'XFORWARD':
            self.output.write('250 Ok\r\n')
            self.output.flush()
        elif command[0] == 'MAIL':
            # Send the XCLIENT command, discard the response and then send the
            # synthesised HELO command and discard its response before issuing
            # the mail command.
            self.command(self.xclient_command)
            self.sendResponse(discard=True)
            name = self.relay_helo if self.relay_helo else self.relay_name
            self.command(['HELO', name])
            self.sendResponse(discard=True)
            super(Relay, self).sendCommandAndResponse(command)
        else:
            super(Relay, self).sendCommandAndResponse(command)