import os
import re
import sys
from select import select

def carp(text):
    import traceback
    stack = traceback.extract_stack()
    caller_frame = stack[-3]
    sys.stderr.write('%s:%s %s: %s' % (caller_frame[0], caller_frame[1],
                                       caller_frame[2], text))
    sys.stderr.flush()

CMD_INFO = 1
CMD_OK = 2
CMD_MORE = 3
CMD_REJECT = 4
CMD_ERROR = 5
CMD_PENDING = 0

class NetCommand(object):
    """
    NetCommand is a class containing methods that implement the
    functionality required for a command-based protocol, for example FTP and
    SMTP.
    """

    def __init__(self, fp=None):
        """
        Constructor for a NetCommand obect. The fp argument should be a
        file-like object that supports two methods:

        fileno() - returns the file descriptor associated with the file
        close() - closes the file

        The Python file and socket objects are compatible with this class.
        """
        if not fp:
            self.open(fp)

    def open(self, fp):
        self.fp = fp
        self.closed = False

    def close(self):
        self.fp.close()
        self.closed = True

    def debug(self, level=None):
        """
        Sets the level of debug information for this object. If level is not
        given then the current state is returned. Otherwise the state is
        changed to level and the previous state returned. 

        Different packages may implement different levels of debug but a
        non-zero value results in copies of all commands and responses also
        being sent to STDERR.

        If level is None then the debug level will be set to the default debug
        level for the class.
        """
        oldval = getattr(self, 'net_cmd_debug', 0)
        if level is not None:
            self.net_cmd_debug = level

        return oldval

    def debugText(self, out, text):
        """
        This method is called to print debugging information. text is the text
        being sent. The method should return the text to be printed. This is
        primarily meant for the use of modules such as FTP where passwords are
        sent, but we do not want to display them in the debugging information.
        """
        dummy = out    
        return text

    def debugPrint(self, out, text):
        """
        Prints debugging information. out denotes the direction, with True
        being data being sent to the server. This method calls debugText
        before printing to STDERR.
        """
        if out:
            sys.stderr.write('>>> %s' % self.debugText(out, text))
        else:
            sys.stderr.write('<<< %s' % self.debugText(out, text))

        sys.stderr.flush()

    def timeout(self):
        return None

    def message(self):
        "Returns the text message returned from the last command."
        return self.net_cmd_resp

    def code(self):
        """
        Returns the 3-digit code from the last command as a string. If a
        command is pending then the value 0 is returned.
        """
        if not hasattr(self, 'net_cmd_code'):
            self.net_cmd_code = '000'

        return self.net_cmd_code

    def status(self):
        """
        Returns the most significant digit of the current status code. If a
        command is pending then CMD_PENDING is returned.
        """
        return int(self.net_cmd_code[0])

    def setStatus(self, code, resp):
        if not isinstance(resp, list):
            resp = [resp]

        self.net_cmd_code = code
        self.net_cmd_resp = resp

    def command(self, args):
        """
        Sends a command to the command server. All arguments are first joined
        with a space character and CRLF is appended, this string is then sent
        to the command server.
        """
        try:
            fd = self.fp.fileno()
        except:
            self.setStatus('599', 'Connection closed')
            return

        if hasattr(self, 'net_cmd_last_ch'):
            self.dataEnd()

        if args:
            cmd = ' '.join([x.replace('\n', ' ') for x in args])
            cmd += '\015\012'

            try:
                cmd_bytes = os.write(fd, cmd)
            except:
                cmd_bytes = None

            if cmd_bytes is None or cmd_bytes != len(cmd):
                try:
                    self.close()
                except:
                    pass

            if self.debug():
                self.debugPrint(1, cmd)

            # Clear the response and set a fictitious response code.
            self.net_cmd_resp = []
            self.net_cmd_code = '000'

    def ok(self):
        """
        Returns True if the last code value was greater than zero and less than
        400. This holds true for most command servers. Servers where this does
        not hold may override this method.
        """
        code = int(self.code())
        return 0 < code < 400

    def unsupported(self):
        """
        Sets the status code to 580 and the response text to
        'Unsupported command'.
        """
        self.net_cmd_resp = ['Unsupported command']
        self.net_cmd_code = '580'

    def getline(self):
        """
        Retrieves one line, delimited by CRLF, from the remote server.
        Returns None upon failure.

        NOTE: If you do use this method for any reason, please remember to add
        some debugPrint calls into your method.
        """
        if not hasattr(self, 'net_cmd_lines'):
            self.net_cmd_lines = []

        if self.net_cmd_lines:
            return self.net_cmd_lines.pop(0)

        partial = getattr(self, 'net_cmd_partial', '')
        fd = self.fp.fileno()
        while not self.net_cmd_lines:
            data_available = select([fd], [], [], self.timeout())[0]
            if data_available:
                buf = os.read(fd, 1024)
                if buf == '':
                    if self.debug():
                        carp('Unexpected EOF on command channel')

                    self.close()
                    return None

                # Prepend the last data read and then break into lines.
                buf = partial + buf
                buf = re.split(r'\015?\012', buf)
                partial = buf.pop(len(buf) - 1)
                self.net_cmd_lines.extend([x + '\n' for x in buf])
            else:
                if self.debug():
                    carp('Timeout')

                return None

        self.net_cmd_partial = partial
        return self.net_cmd_lines.pop(0)

    def ungetline(self, line):
        "Ungets a line of text from the server."
        if not hasattr(self, 'net_cmd_lines'):
            self.net_cmd_lines = []

        self.net_cmd_lines.insert(0, line)

    def parseResponse(self, line):
        """
        This method is called by response as a method with one argument. It
        should return an array of 2 values, the 3-digit status code and a flag
        which is true when this is part of a multi-line response and this line
        is not the list.
        """
        match = re.search(r'^(\d\d\d)(.?)(.*)', line)
        if match:
            return match.group(3), match.group(1), match.group(2) == '-'
        else:
            return line, None, False

    def response(self):
        """
        Obtains a response from the server. Upon success the most significant
        digit of the status code is returned. Upon failure, timeout etc.,
        CMD_ERROR is returned.
        """
        if not hasattr(self, 'net_cmd_resp'):
            self.net_cmd_resp = []

        more = True
        while more:
            line = self.getline()
            if line is None:
                return CMD_ERROR

            if self.debug():
                self.debugPrint(0, line)

            line, code, more = self.parseResponse(line)
            if code is None:
                self.ungetline(line)
                break

            self.net_cmd_code = code
            self.net_cmd_resp.append(line)

        return int(code[0])

    def readUntilDot(self, fp=None):
        """
        Reads data from the remote server until a line consisting of a single
        '.'. Any lines starting with '..' will have one of the '.'s removed.

        Returns a reference to a list containing the lines, or None upon
        failure.
        """
        array = []
        dotend_pattern = re.compile(r'^\.\r?\n')
        while True:
            line = self.getline()
            if line is None:
                return None

            if self.debug() & 4:
                self.debugPrint(0, line)

            match = dotend_pattern.search(line)
            if match:
                break

            if fp:
                os.write(fp.fileno(), line)
            else:
                array.append(line)

        return array

    def dataSend(self, lines):
        """
        Sends data to the remote server, converting LF to CRLF. Any line
        starting with a '.' will be prefixed with another '.'.
        """
        line = ''.join(lines)
        try:
            fd = self.fp.fileno()
        except:
            return 0

        last_ch = getattr(self, 'net_cmd_last_ch', None)
        if last_ch is None:
            last_ch = '\012'
            self.net_cmd_last_ch = last_ch

        if len(line) == 0:
            return 1

        if self.debug():
            for b in re.split(r'\n', line):
                self.debugPrint(1, b + '\n')

        if '\r' != '\015':
            line = line.replace('\r\n', '\015\012')

        first_ch = ''
        if last_ch == '\015':
            if line.find('\012') == 0:
                first_ch = '\012'
        elif last_ch == '\012':
            if line.find('.') == 0:
                first_ch = '.'

        line = first_ch + re.sub(r'\015?\012(\.?)', r'\015\012\1\1', line)
        self.net_cmd_last_ch = line[-1]
        num_bytes = len(line)
        offset = 0
        while num_bytes:
            output = select([], [fd], [], self.timeout())[1]
            if output:
                try:
                    bytes_written = os.write(fd, line[offset:num_bytes])
                except Exception, exc:
                    if self.debug():
                        carp(str(exc))

                    return None

                num_bytes -= bytes_written
                offset += bytes_written
            else:
                if self.debug():
                    carp('Timeout')

                return None

        return 1

    def rawDataSend(self, lines):
        "Sends data to the remote server without performing any conversions."
        line = ''.join(lines)
        try:
            fd = self.fp.fileno()
        except:
            return 0

        num_bytes = len(line)
        if num_bytes == 0:
            return 1

        if self.debug():
            sys.stderr.write('>>> ')
            sys.stderr.write('\n>>> '.join(re.split(r'\n', line)))
            sys.stderr.write('\n')
            sys.stderr.flush()

        offset = 0
        while num_bytes:
            output = select([], [fd], [], self.timeout())[1]
            if output:
                try:
                    bytes_written = os.write(fd, line[offset:num_bytes])
                except Exception, exc:
                    if self.debug():
                        carp(str(exc))

                    return None

                num_bytes -= bytes_written
                offset += bytes_written
            else:
                if self.debug():
                    carp('Timeout')

                return None

        return 1

    def dataEnd(self):
        """
        Ends the sending of data to the remote server. This is done by ensuring
        that the data already sent ends with CRLF then sending '.CRLF' to end
        the transmission. Once this data has been sent dataEnd calls response
        and returns True if response returns CMD_OK.
        """
        try:
            fd = self.fp.fileno()
        except:
            return 0

        tosend = ''
        ch = getattr(self, 'net_cmd_last_ch', None)
        if ch is None:
            return 1
        elif ch != '\012':
            tosend = '\015\012'

        tosend += '.\015\012'

        if self.debug():
            self.debugPrint(1, '.\n')

        os.write(fd, tosend)
        if hasattr(self, 'net_cmd_last_ch'):
            del self.net_cmd_last_ch

        return self.response() == CMD_OK
