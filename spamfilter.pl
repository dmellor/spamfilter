#!/usr/bin/perl

use strict;

use constant VIRUS => 29;
use constant SPAM => 30;
use constant TEMPORARY_FAILURE => 73;

my ($cfg, $home);

# Check in the BEGIN block if the connection to the SMTP server has been made
# from an interface on which filtering is to be performed. If not, then we
# immediately exec an instance of qmail-queue, which will prevent all of the
# SpamAssassin code from ever being compiled. Note that qmail-smtpd has already
# performed a chdir to /var/qmail before execing this script.
BEGIN {
	use lib $ENV{SPAMFILTER_HOME};
	use Config::IniFiles;

	$home = $ENV{SPAMFILTER_HOME};
	$cfg = new Config::IniFiles(-file => "$home/spamfilter.ini");
	my @interfaces = $cfg->val('General', 'interfaces');
	if (grep($_ eq $ENV{TCPLOCALIP}, @interfaces) == 0 ||
		defined($ENV{RELAYCLIENT})) {
		exec 'bin/qmail-queue';
	}
}

# Load the remainder of the modules.
use MySpamAssassin;
use MysqlAutoWhitelist;
use DBI;
use IO::Socket::INET;

main();

sub main
{
	# Read in the message and the envelope headers.
	my $message = join '', <STDIN>;
	open SOUT, '<&1';
	my $envelope = <SOUT>;
	close SOUT;

	# If the message is above a certain size, then automatically accept it.
	if (length($message) > $cfg->val('General', 'maxMessageLength')) {
		# The AcceptMessage subroutine returns the exit code of qmail-queue,
		# which should be returned to qmail-smtpd.
		exit AcceptMessage($envelope, \$message, 0, undef);
	}

	# Open a connection to the database to fetch the whitelists.
	my $dsn = $cfg->val('AutoWhitelist', 'dsn');
	my $user = $cfg->val('AutoWhitelist', 'user');
	my $password = $cfg->val('AutoWhitelist', 'password');
	my $dbh = DBI->connect($dsn, $user, $password,
		{ PrintError => 0, RaiseError => 1, AutoCommit => 0 });
	$dbh->do('LOCK TABLE auto_whitelist IN ACCESS EXCLUSIVE MODE');
#	$dbh->do('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');

	my $returnCode;
	eval { $returnCode = ProcessMessage(\$message, $envelope, $dbh) };
	my $status = $@;
	if ($status) {
		$dbh->rollback;
		$dbh->disconnect;
		exit TEMPORARY_FAILURE;
	}
	else {
		$dbh->commit;
		$dbh->disconnect;
		exit $returnCode;
	}
}

sub ProcessMessage
{
	my ($message, $envelope, $dbh) = @_;

	# Create the the auto-whitelist factory.
	my $factory = new MysqlAutoWhitelist($dbh);

	# Determine who sent the mail and to whom it is to be delivered.
	my ($envelopeFrom, @envelopeTo) = ProcessEnvelope($envelope);

	# If the all of the recipients are whitelisted, then accept the message.
	my $sth = $dbh->prepare(
		'SELECT rcpt_to FROM whitelist_to WHERE NOT filter_content');
	$sth->execute;
	my $whitelistTo = $sth->fetchall_arrayref;
	my @whitelistRcpts = grep {
		isAddressWhitelisted(lc $_, $whitelistTo)
	} @envelopeTo;

	if (scalar(@whitelistRcpts) == scalar(@envelopeTo)) {
		return AcceptMessage($envelope, $message, 1, $dbh);
	}

	# Check the message and accept it if it is not spam.
	my $status = CheckMessage($message, \@envelopeTo, $factory);
	if (!$status->is_spam()) {
		return AcceptMessage($envelope, $message, 1, $dbh);
	}
	elsif ($status->get_hits() < $cfg->val('General', 'rejectThreshold')) {
		$status->rewrite_mail();
		my $spamMessage = $status->get_full_message_as_text();
		$message = \$spamMessage;
		return AcceptMessage($envelope, $message, 0, $dbh);
	}

	# The message is spam. In case of false positives, add the message to the
	# database.
	$sth = $dbh->prepare(
		'INSERT INTO saved_mail
			(mail_from, ip_address, contents, hits, tests, created)
			VALUES (?, ?, ?, ?, ?, NOW())');

	$sth->execute($envelopeFrom, $ENV{TCPREMOTEIP}, $$message,
		$status->get_hits(), $status->get_names_of_tests_hit());

	$sth = $dbh->prepare(
		'INSERT INTO saved_mail_recipients (recipient, saved_mail_id)
			VALUES (?, CURRVAL(\'saved_mail_id_seq\'))');

	map { $sth->execute($_) } @envelopeTo;

	# Return an error status to qmail-smtpd.
	return SPAM;
}

sub ProcessEnvelope
{
	my $envelope = shift;

	# Determine who sent the mail and to whom it is to be delivered.
	my ($envelopeFrom, @envelopeTo) = split /\x00+/, $envelope;
	$envelopeFrom =~ s/^F//;
	@envelopeTo = map { /^T(.*)/; lc $1 } @envelopeTo;

	return ($envelopeFrom, @envelopeTo);
}

sub CheckMessage
{
	my ($message, $recipients, $factory) = @_;

	# Create the SpamAssassin instance and set the factory instance.
	my $assassin = new MySpamAssassin({
		dont_copy_prefs => 1,
		home_dir_for_helpers => $home
	});

	# Make sure that the init method is called before setting the persistent
	# address list factory, otherwise the call to check_message_text will
	# override the setting. Since we are not using per-user preferences, a zero
	# value is passed to the init method.
	$assassin->init(0);
	$assassin->set_persistent_address_list_factory($factory);
	my $config = $assassin->{conf};

	# Add the user-defined whitelists to the SpamAssassin configuration.
	my $dbh = $factory->getDbHandle();
	my $sth = $dbh->prepare(
		'SELECT c.mail_from FROM user_addresses AS a JOIN
			whitelist_from AS b ON a.user_id = b.user_id JOIN
			mail_from_addresses AS c ON c.id = b.mail_from_id
			WHERE a.address = ?');

	foreach my $recipient (@$recipients) {
		$sth->execute($recipient);
		while (my $row = $sth->fetchrow_arrayref()) {
			$config->add_to_addrlist('whitelist_from', $row->[0]);
		}
	}

	# Add the user-defined blacklists to the SpamAssassin configuration.
	$sth = $dbh->prepare(
		'SELECT blacklist.mail_from FROM blacklist, user_addresses
			WHERE user_addresses.address = ? AND
				user_addresses.user_id = blacklist.user_id');

	foreach my $recipient (@$recipients) {
		$sth->execute($recipient);
		while (my $row = $sth->fetchrow_arrayref()) {
			$config->add_to_addrlist('blacklist_from', $row->[0]);
		}
	}

	# Return the PerMsgStatus object that specifies the status of the
	# message.
	return $assassin->check_message_text($$message);
}

sub AcceptMessage
{
	# The message is passed by reference as it could potentially be large.
	my ($envelope, $message, $checkVirus, $dbh) = @_;

	if ($checkVirus) {
		return VIRUS if CheckVirus($envelope, $message, $dbh);
	}

	# Fork a child process to queue the message.
	pipe ENVREAD, ENVWRITE;
	pipe MSGREAD, MSGWRITE;
	my $pid;
	unless ($pid = fork) {
		defined $pid or die "Could not fork qmail-queue, $!";

		# Copy the read descriptors in the child to file descriptors 0 and 1.
		close ENVWRITE;
		close MSGWRITE;
		close STDIN;
		close STDOUT;
		open STDIN, '<&MSGREAD';
		open STDOUT, '<&ENVREAD';
		close MSGREAD;
		close ENVREAD;

		# Invoke qmail-queue.
		exec 'bin/qmail-queue';
	}

	# Write the envelope and message to qmail-queue.
	close ENVREAD;
	close MSGREAD;
	print MSGWRITE $$message;
	close MSGWRITE;
	print ENVWRITE $envelope;
	close ENVWRITE;

	# Wait for qmail-queue to finish and then return its exit status.
	waitpid $pid, 0;
	return $? >> 8;
}

sub CheckVirus
{
	# The message is passed by reference.
	my ($envelope, $message, $dbh) = @_;

	my $socket = new IO::Socket::INET(
		PeerAddr => 'localhost',
		PeerPort => 3310,
		Type => SOCK_STREAM,
		Timeout => 5)
		or die $@;

	print $socket "STREAM\n";
	my $response = <$socket>;
	my ($port) = $response =~ /PORT\s+(\d+)/;
	my $stream = new IO::Socket::INET(
		PeerAddr => 'localhost',
		PeerPort => $port,
		Type => SOCK_STREAM,
		Timeout => 5)
		or die $@;

	print $stream $$message;
	$stream->close;
	$response = <$socket>;
	$socket->close;
	chomp $response;
	if ($response =~ /(\S+)\s+FOUND$/) {
		my $virus = $1;
		my ($envelopeFrom, @envelopeTo) = ProcessEnvelope($envelope);
		my $sth = $dbh->prepare(
			'INSERT INTO viruses
				(mail_from, ip_address, contents, virus, created)
				VALUES (?, ?, ?, ?, NOW())');
		$sth->execute($envelopeFrom, $ENV{TCPREMOTEIP}, $$message, $virus);

		$sth = $dbh->prepare(
			'INSERT INTO virus_recipients (recipient, virus_id)
				VALUES (?, CURRVAL(\'viruses_id_seq\'))');

		map { $sth->execute($_) } @envelopeTo;
		return 1;
	}

	return undef;
}

sub acceptAddress
{
	my ($address, $pattern) = @_;

	$pattern =~ s/\@/\\@/g;
	$pattern =~ s/\+/\\+/g;
	$pattern =~ s/\./\\./g;
	$pattern =~ s/\*/.*/g;

	return $address =~ /^$pattern$/;
}

sub isAddressWhitelisted
{
	my ($address, $whitelist) = @_;

	foreach (@$whitelist) {
		return 1 if acceptAddress($address, $_->[0]);
	}

	return undef;
}
