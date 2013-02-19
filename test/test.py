import sys
import re
from subprocess import *

message = '''From: foo@example.com
To: dmellor@whistlingcat.com
Subject: Test

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
'''

message = '\r\n'.join(message.split('\n'))
message += '.\r\n'

helo_command = ('EHLO', 'granite.whistlingcat.com')
message_commands = (('XFORWARD', 'NAME=foo.example.com', 'ADDR=1.2.3.4'),
                    ('XFORWARD', 'PROTO=ESMTP', 'HELO=foo.example.com',
                     'SOURCE=REMOTE'),
                    ('MAIL', 'FROM:<foo@example.com>'),
                    ('RCPT', 'TO:<dmellor@whistlingcat.com>'),
                    ('DATA', message))
quit_command = ('QUIT',)

def main(num_messages):
    smtp = Popen('/home/spamfilter/test/spamcheck2', shell=False, stdin=PIPE,
                 stdout=PIPE)
    readResponse(smtp)
    sendCommand(smtp, helo_command)
    for i in range(num_messages):
        for command in message_commands:
            sendCommand(smtp, command)

    sendCommand(smtp, quit_command)

def sendCommand(smtp, command):
    if command[0] != 'DATA':
        sending = ' '.join(command)
        print 'Sending %s' % sending
        smtp.stdin.write(sending)
        smtp.stdin.write('\r\n')
        readResponse(smtp)
    else:
        print 'Sending DATA'
        smtp.stdin.write(command[0])
        smtp.stdin.write('\r\n')
        readResponse(smtp)
        smtp.stdin.write(command[1])
        readResponse(smtp)

def readResponse(smtp):
    more_input = re.compile(r'^\d+-')
    while True:
        output = smtp.stdout.readline()
        if not output:
            print 'Process exited'
            sys.exit(0)

        print output.strip()
        if not more_input.search(output):
            break

if __name__ == '__main__':
    main(int(sys.argv[1]))
