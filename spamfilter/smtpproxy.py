import socket
import sys
import re

import spamfilter.netcmd as netcmd


class SmtpProxy(netcmd.NetCommand):
    """
    This class can be used to implement an after-queue content filter for
    Postfix. It sits between an SMTP client and an SMTP server, reading
    commands from the client and passing them on unmodified to the server, and
    then sending the responses from the server back to the client. The proxy
    should be set to run via the Postfix spawn service, which means that all
    communication with the SMTP client will be performed via stdin and stdout.
    The proxy examines the contents of the DATA command sent by the SMTP
    client, and either passes the contents on to the SMTP server or terminates
    the network connection to the SMTP server. In this latter case, it still
    reports to the SMTP client that the mail has been accepted - this behaviour
    is required in order to implement an after-queue content filter for
    Postfix. A subclass of this class would override the check_message method
    to quarantine the message if it is identified as spam or if it contains a
    virus.
    """

    def __init__(self, smtp_input=sys.stdin, smtp_output=sys.stdout,
                 host='localhost', port=25):
        super(SmtpProxy, self).__init__()
        self.host = host
        self.port = port
        self.rcpt_to = []
        self.bounce = None
        self.remote_addr = None
        self.remote_host = None
        self.error_response = None

        # Open a connection to the remote server.
        self.input = smtp_input
        self.output = smtp_output
        self.open_connection()
        self.send_response()

    def open_connection(self):
        # Create the connection to the remote server and get the file
        # descriptor from it.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        self.open(s)

    def process_message(self):
        while True:
            line = self.input.readline()
            if line == '':
                break

            command = line.split()
            if command[0] == 'XFORWARD':
                self.xforward(command)
                self.send_command_and_response(command)
            elif command[0] == 'MAIL':
                self.mail(command)
                self.send_command_and_response(command)
            elif command[0] == 'RCPT':
                ok, rcpt = self.rcpt(command)
                if ok:
                    self.send_command_and_response(command)
                else:
                    self.unknown_user(rcpt)
            elif command[0] == 'DATA':
                self.data(command)

                # Reset the attributes in case more than one message is being
                # processed.
                self.rcpt_to = []
                self.bounce = None
                self.remote_addr = None
                self.remote_host = None
                self.error_response = None
            else:
                self.send_command_and_response(command)

    def send_command_and_response(self, command):
        processed = False
        if self.closed:
            # If this point is reached then another message is being sent to
            # the remote server after the previous message was identified as
            # spam. Open up a new connection to the remote server, discard the
            # greeting and fake an EHLO command. However, if the command is
            # QUIT, then we simply send a fake '221 Bye' response back to the
            # first server.
            if command[0] != 'QUIT':
                self.open_connection()
                self.send_response(discard=True)
                self.command(['EHLO', 'localhost'])
                self.send_response(discard=True)
            else:
                self.output.write('221 Bye\r\n')
                self.output.flush()
                processed = True

        # Send the command and its response.
        if not processed:
            self.command(command)
            self.send_response()

    def send_response(self, discard=False):
        self.response()
        if not discard:
            self.print_response()

    def print_response(self):
        # Get the response. NetCommand strips the code from each line and
        # replaces the \r\n sequences at the end of the line with a bare
        # linefeed.
        message = self.message()

        def reformat(line):
            line = line.rstrip('\n')
            return '-%s\r\n' % line

        message = [reformat(x) for x in message]
        message[-1] = re.sub('^-', ' ', message[-1])
        code = self.code()
        self.output.writelines(['%s%s' % (code, x) for x in message])
        self.output.flush()

    def unknown_user(self, rcpt):
        self.set_status('550', 'User unknown: <%s>' % rcpt)
        self.print_response()

    def xforward(self, command):
        # Extract the remote IP address and hostname and save them for logging
        # purposes.
        regexp = re.compile('^(ADDR|HELO)=(.*)')
        for token in command:
            match = regexp.search(token)
            if match:
                if match.group(1) == 'ADDR':
                    self.remote_addr = match.group(2)
                else:
                    self.remote_host = match.group(2).lower()

    def data(self, command):
        self.command(command)
        cmd_status = self.response()
        self.print_response()
        if cmd_status != netcmd.CMD_MORE:
            return

        # Read the email message, converting \r\n sequences to \n and
        # converting lines that begin with two periods to a single period.
        message = []
        eol_regexp = re.compile(r'^\.\r?\n$')
        convert_regexp = re.compile(r'\r?\n$')
        doubledot_regexp = re.compile(r'^\.\.')
        while True:
            # If the first server has prematurely closed the connection, then
            # we return immediately - the processMessage method will take care
            # of closing the connection to the second server.
            line = self.input.readline()
            if line == '':
                return

            if eol_regexp.search(line):
                break

            line = convert_regexp.sub('\n', line)
            line = doubledot_regexp.sub('.', line)
            message.append(line)

        # Check the message.
        if self.check_message(message):
            # The message passed the check, so send it to the second server.
            # The dataend method calls the response method, so the response
            # message can be sent to the first server immediately after calling
            # dataend.
            self.data_send(message)
            self.data_end()
            self.print_response()
        else:
            # The message did not pass the check. The connection to the second
            # server is closed immediately, and an error response is sent back
            # to the first server.
            self.close()
            response = re.sub(r'\r?\n?$', '\r\n', self.error_response)
            self.output.write(response)
            self.output.flush()

    def data_send(self, message):
        # NetCommand has a bug in its datasend method, as it does not clear the
        # previous response, This causes the response from the dataend method
        # to be garbled, as it contains the previous response prepended to it.
        # We override the method here to clear the response before sending the
        # data.
        self.set_status('000', [])
        super(SmtpProxy, self).data_send(message)

    def check_message(self, message):
        """
        This method should be overridden in a subclass to perform the checking
        operation.
        """
        return True

    def mail(self, command):
        addr_regexp = re.compile(r'<(.*)>')
        i = 1
        for token in command[1:]:
            match = addr_regexp.search(token)
            if match:
                address = match.group(1).strip()
                if address:
                    self.bounce = address
                    command[i] = addr_regexp.sub(
                        '<' + self.generate_srs(address) + '>',
                        command[i])

                return
            else:
                i += 1

    def generate_srs(self, bounce):
        # This method is overridden in spamcheck.py to generate SRS addresses.
        return bounce

    def reverse_srs(self, address):
        # This method is overridden in spamcheck.py to generate SRS addresses.
        return address

    def rcpt(self, command):
        addr_regexp = re.compile('<(.*)>')
        i = 1
        for token in command[1:]:
            match = addr_regexp.search(token)
            if match:
                rcpt = match.group(1).lstrip().rstrip()
                if re.search(r'^SRS[01]=', rcpt):
                    actual_rcpt = self.reverse_srs(rcpt)
                    if not actual_rcpt:
                        return False, rcpt
                    else:
                        rcpt = actual_rcpt
                        command[i] = addr_regexp.sub(
                            '<' + rcpt + '>',
                            command[i])

                self.rcpt_to.append(rcpt.lower())
                return True, rcpt
            else:
                i += 1

        return False, ''
