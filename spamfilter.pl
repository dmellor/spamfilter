#!/usr/bin/perl
# $Id$

use strict;

# Add the directory containing the spamfilter scripts to the Perl include path.
my $home;

BEGIN {
	$home = shift;
	unshift @INC, $home;
}

package SpamFilter;

use BeforeQueueProxy;
use MySpamAssassin;
use SqlAutoWhitelist;
use Mail::SpamAssassin::Message;
use DBI;
use IO::Socket::INET;

our @ISA = qw(BeforeQueueProxy);

sub checkMessage
{
	my ($self, $message) = @_;

	print STDERR "Entering check message\n" if $self->debug;

	# If the remote address is in the POP before SMTP table, then we do not
	# perform any checks.
	my $addr = $self->getAttribute('remoteAddr');
	my $cfg = $self->getArgument('Config');
	my $db = $cfg->val('General', 'popDb');
#	open POSTMAP, "/usr/sbin/postmap -q $addr $db |"
#		or die 'Could not access db';
#	my $line = <POSTMAP>;
#	close POSTMAP;
#	return 1 if $line =~ /^ok/;

	# The client is an external client - perform the spam and virus checks.
	my $dbh = $self->getArgument('Dbh');
	$self->setAttribute('dbh', $dbh);
	my $retries = 0;
	my $ok;
	my $retry;
	my $status;
	while ($retries < 2) {
		($ok, $retry, $status) = $self->performChecks($message, $retries);
		last unless $retry;
		$retries++;
		sleep 10;
	}

	$self->setErrorResponse("451 $status") if $status;
	return $ok;
}

sub performChecks
{
	my ($self, $message, $attempt) = @_;

	my $dbh = $self->getAttribute('dbh');
	my $ok;
	eval {
		if ($attempt == 0) {
#			$dbh->do('LOCK TABLE auto_whitelist IN ACCESS EXCLUSIVE MODE');
			$dbh->do('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
		}

		print STDERR "Calling spamcheck\n" if $self->debug;
		$ok = $self->spamcheck($message);
		print STDERR "spamchek returned $ok\n" if $self->debug;
		if ($ok && $self->getAttribute('virusCheck')) {
			print STDERR "Calling viruscheck\n" if $self->debug;
			$ok = $self->viruscheck($message);
			print STDERR "viruscheck returned $ok\n" if $self->debug;
		}
	};

	my $status = $@;
	if ($status) {
		$dbh->rollback;
		$status =~ s/\r?\n/ /g;
		print STDERR "rollback - status = $status\n" if $self->debug;
		return (undef, 1, $status);
	}
	else {
		$dbh->commit;
		return $ok;
	}
}

sub spamcheck
{
	my ($self, $message) = @_;

	# If the message is above a certain size, then automatically accept it.
	my $cfg = $self->getArgument('Config');
	my $maxLength = $cfg->val('General', 'maxMessageLength');
	my $length = 0;
	foreach my $line (@$message) {
		$length += length($line);
		if ($length > $maxLength) {
			$self->setAttribute('virusCheck', 0);
			return 1;
		}
	}

	# Determine who sent the mail and to whom it is to be delivered.
	my $envelopeFrom = $self->getMailFrom;
	my $envelopeTo = $self->getRcptTo;

	# If the all of the recipients are whitelisted, then accept the message.
	my $dbh = $self->getArgument('Dbh');
	my $sth = $dbh->prepare(
		'SELECT rcpt_to FROM whitelist_to WHERE NOT filter_content');
	$sth->execute;
	my $whitelistTo = $sth->fetchall_arrayref;
	my @whitelistRcpts = grep {
		isAddressWhitelisted(lc $_, $whitelistTo)
	} @$envelopeTo;

	if (scalar(@whitelistRcpts) == scalar(@$envelopeTo)) {
		$self->setAttribute('virusCheck', 1);
		return 1;
	}

	# Check the message and accept it if it is not spam.
	my $factory = new SqlAutoWhitelist($dbh);
	my $status = spamAssassinCheck($message, $envelopeTo, $factory);
	if (!$status->is_spam) {
		$self->setAttribute('virusCheck', 1);
		return 1;
	}
	elsif ($status->get_hits < $cfg->val('General', 'rejectThreshold')) {
		@$message = ($status->rewrite_mail);
		$self->setAttribute('virusCheck', 0);
		return 1;
	}

	# The message is spam. In case of false positives, add the message to the
	# database.
	$sth = $dbh->prepare(
		'INSERT INTO saved_mail
			(mail_from, ip_address, contents, hits, tests, created)
			VALUES (?, ?, ?, ?, ?, NOW())');

	$sth->execute($envelopeFrom, $self->getAttribute('remoteAddr'),
		join('', @$message), $status->get_hits,
		$status->get_names_of_tests_hit);

	$sth = $dbh->prepare(
		'INSERT INTO saved_mail_recipients (recipient, saved_mail_id)
			VALUES (?, CURRVAL(\'saved_mail_id_seq\'))');
	map { $sth->execute($_) } @$envelopeTo;

	# Reject the message.
	$self->setErrorResponse(
		'550 Message was identified as spam and is rejected');
	return undef;
}

sub spamAssassinCheck
{
	my ($message, $recipients, $factory) = @_;

	my $messageObj = new Mail::SpamAssassin::Message({ message => $message });

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
	return $assassin->check($messageObj);
}

sub isAddressWhitelisted
{
	my ($address, $whitelist) = @_;

	foreach (@$whitelist) {
		return 1 if acceptAddress($address, $_->[0]);
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

sub viruscheck
{
	my ($self, $message) = @_;

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

	print $stream @$message;
	$stream->close;
	$response = <$socket>;
	$socket->close;
	chomp $response;
	if ($response =~ /(\S+)\s+FOUND$/) {
		my $virus = $1;
		my $dbh = $self->getAttribute('dbh');
		my $sth = $dbh->prepare(
			'INSERT INTO viruses
				(mail_from, ip_address, contents, virus, created)
				VALUES (?, ?, ?, ?, NOW())');
		$sth->execute($self->getMailFrom, $self->getAttribute('remoteAddr'),
			join('', @$message), $virus);

		$sth = $dbh->prepare(
			'INSERT INTO virus_recipients (recipient, virus_id)
				VALUES (?, CURRVAL(\'viruses_id_seq\'))');

		map { $sth->execute($_) } @{$self->getRcptTo};

		# Reject the message.
		$self->setErrorResponse(
			'550 Message contains a virus and was rejected');
		return undef;
	}

	return 1;
}


package main;

use Config::IniFiles;

main();

sub main
{
	# Open a connection to the database.
	my $cfg = new Config::IniFiles(-file => "$home/spamfilter.ini");
	my $dsn = $cfg->val('AutoWhitelist', 'dsn');
	my $user = $cfg->val('AutoWhitelist', 'user');
	my $password = $cfg->val('AutoWhitelist', 'password');
	my $dbh = DBI->connect($dsn, $user, $password,
		{ PrintError => 0, RaiseError => 1, AutoCommit => 0 });

	# Open a log file for debugging if debugging has been specified.
	my $debug = $cfg->val('General', 'debug');
	if ($debug) {
		close STDERR;
		open STDERR, ">>$home/spamfilter.$$.log";
		STDERR->autoflush(1);
	}

	# Create the SMTP proxy and process the message.
	my $proxy = new SpamFilter(
		PeerAddr => $cfg->val('General', 'smtpServer'),
		PeerPort => $cfg->val('General', 'smtpPort'),
		Home => $home,
		Config => $cfg,
		Dbh => $dbh);

	$proxy->debug(1) if $debug;

	print STDERR "Calling processMessage\n" if $debug;
	$proxy->processMessage;
	$dbh->disconnect;
}
