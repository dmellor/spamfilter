# $Id$

# This class can be used to implement a before-queue content filter for
# Postfix. It sits between two SMTP servers, reading commands from one server
# and passing them on unmodified to the second server, and then sending the
# responses from the second server back to the first server. The proxy should
# be set to run via the Postfix spawn service, which means that all
# communication with the first SMTP server will be performed via stdin and
# stdout. The proxy examines the contents of the DATA command sent by the first
# SMTP server, and either passes the contents on to the second SMTP server or
# terminates the network connection to the second SMTP server and returns an
# error code to the first SMTP server.

package BeforeQueueProxy;

use strict;

use Net::Cmd;
use IO::Socket::INET;

our @ISA = qw(Net::Cmd IO::Socket::INET);

sub new
{
	my ($self, %args) = @_;

	my $type = ref($self) || $self;
	my $obj = $type->SUPER::new(
		PeerAddr => $args{PeerAddr},
		PeerPort => $args{PeerPort},
		Proto => 'tcp');
	$obj->autoflush(1);
	STDOUT->autoflush(1);
	${*$obj}{rcptTo} = [];

	# Store the argument values in the object so that subclasses can retrieve
	# configuration information.
	${*$obj}{arguments} = \%args;

	# Send the initial greeting response from the second server to the first
	# server.
	$obj->sendResponse;

	return $obj;
}

sub getArgument
{
	my ($self, $argName) = @_;

	my $args = ${*$self}{arguments};
	return $args->{$argName};
}

sub setArgument
{
	my ($self, $argName, $argValue) = @_;

	my $args = ${*$self}{arguments};
	$args->{$argName} = $argValue;
}

sub processMessage
{
	my $self = shift;

	while (my $line = <STDIN>) {
		# Extract the command.
		my @command = split ' ', $line;
		if ($command[0] eq 'XFORWARD') {
			$self->xforward(@command);
			$self->sendCommandAndResponse(@command);
		}
		elsif ($command[0] eq 'MAIL') {
			$self->mail(@command);
			$self->sendCommandAndResponse(@command);
		}
		elsif ($command[0] eq 'RCPT') {
			$self->rcpt(@command);
			$self->sendCommandAndResponse(@command);
		}
		elsif ($command[0] eq 'DATA') {
			$self->data(@command);
		}
		else {
			$self->sendCommandAndResponse(@command);
		}
	}

	$self->close unless ${*$self}{errorResponse};
}

sub sendCommandAndResponse
{
	my ($self, @command) = @_;

	unless (${*$self}{errorResponse}) {
		$self->command(@command);
		$self->sendResponse;
	}
	else {
		print "221 Proxy closing transmission channel\r\n";
	}
}

sub sendResponse
{
	my $self = shift;

	$self->response;
	$self->printResponse;
}

sub printResponse
{
	my $self = shift;

	# Get the response. Net::Cmd strips the code from each line and replaces
	# the \r\n sequence at the end of the line with a bare linefeed.
	my @message = $self->message;
	@message = map { chomp; $_ = "-$_\r\n" } @message;
	$message[$#message] =~ s/^-/ /;
	my $code = $self->code;
	print map { "$code$_" } @message;
}

sub xforward
{
	my ($self, @command) = @_;

	# Extract the remote IP address, and save it for logging purposes.
	foreach (@command) {
		if (/^ADDR=(.*)/) {
			$self->setAttribute('remoteAddr', $1);
		}
	}
}

sub getAttribute
{
	my ($self, $key) = @_;

	return ${*$self}{$key};
}

sub setAttribute
{
	my ($self, $key, $value) = @_;

	${*$self}{$key} = $value;
}

sub data
{
	my ($self, @command) = @_;

	$self->command(@command);
	my $cmdStatus = $self->response;
	$self->printResponse;
	return unless $cmdStatus == CMD_MORE;

	# Read the email message, converting \r\n sequences to \n and converting
	# lines that begin with two periods to a single period.
	my @message = ();
	while (1) {
		# If the external server has prematurely closed the connection, then we
		# immediately return - the processMessage method will take care of
		# closing the connection to the internal server.
		my $line = <STDIN>;
		return unless $line;
		print STDERR "Read: $line" if $self->debug;
		last if $line =~ /^\.\r?\n$/;
		$line =~ s/\r?\n$/\n/;
		$line =~ s/^\.\././;
		push @message, $line;
	}

	# Check the message.
	if ($self->checkMessage(\@message)) {
		# The message passed the check, so send it to the second server. The
		# dataend method calls the response method, so the response message
		# can be sent to the first server immediately after calling dataend.
		$self->datasend(\@message);
		$self->dataend;
		$self->printResponse;
	}
	else {
		# The message did not pass the check. The connection to the second
		# server is immediately closed, and an error response is sent back to
		# first server.
		$self->close;
		my $errorResponse = ${*$self}{errorResponse};
		$errorResponse =~ s/\r?\n?$/\r\n/;
		print $errorResponse;
	}
}

# Net::Cmd has a bug in its datasend method, as it does not clear the previous
# response. This causes the response from the dataend method to be garbled, as
# it contains the previous response prepended to it. We override the method
# here to clear the response before sending the data.
sub datasend
{
	my ($self, $message) = @_;

	$self->set_status("000", []);
	$self->SUPER::datasend($message);
}

sub setErrorResponse
{
	my ($self, $errorResponse) = @_;

	${*$self}{errorResponse} = $errorResponse;
}

sub checkMessage
{
	# This method should be overridden in a subclass to perform the checking
	# operation.
	return 1;
}

sub mail
{
	my ($self, @command) = @_;

	shift @command;
	while (@command) {
		my $token = shift @command;
		my ($mailFrom) = $token =~ /<(.*)>/;
		$mailFrom =~ s/^\s+//;
		$mailFrom =~ s/\s+$//;
		if ($mailFrom) {
			${*$self}{mailFrom} = lc $mailFrom;
			return;
		}
	}
}

sub getMailFrom
{
	my $self = shift;

	return ${*$self}{mailFrom};
}

sub rcpt
{
	my ($self, @command) = @_;

	shift @command;
	while (@command) {
		my $token = shift @command;
		my ($rcptTo) = $token =~ /<(.*)>/;
		$rcptTo =~ s/^\s+//;
		$rcptTo =~ s/\s+$//;
		if ($rcptTo) {
			push @{${*$self}{rcptTo}}, lc $rcptTo;
			return;
		}
	}
}

sub getRcptTo
{
	my $self = shift;

	return ${*$self}{rcptTo};
}

1;
