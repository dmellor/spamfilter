#!/usr/bin/perl
# $Id$

use strict;

use Config::IniFiles;
use DBI;
use IO::Handle;

use constant ACCEPTED => 'dunno';
use constant REJECTED =>
	'defer_if_permit System temporarily unavailable, please try again later';

STDOUT->autoflush(1);
main(@ARGV);

sub main
{
	my $home = shift;
	my $cfg = new Config::IniFiles(-file => "$home/spamfilter.ini");
	my $dsn = $cfg->val('Greylist', 'dsn');
	my $user = $cfg->val('Greylist', 'user');
	my $password = $cfg->val('Greylist', 'password');
	my $dbh = DBI->connect($dsn, $user, $password,
		{ PrintError => 0, RaiseError => 1, AutoCommit => 0 });

	my $debug = $cfg->val('Greylist', 'debug');
	if ($debug) {
		close STDERR;
		open STDERR, ">>$home/greylist.$$.log";
		STDERR->autoflush(1);
	}

	process($dbh, $debug);
	$dbh->disconnect;
}

sub process
{
	my ($dbh, $debug) = @_;

	# Extract the greylist information from the policy delegation information
	# sent by Postfix.
	my ($ip, $mailFrom, $rcptTo, $helo);
	while (<STDIN>) {
		print STDERR "Read: $_" if $debug;
		last if $_ eq "\n";
		chomp;
		my ($name, $value) = /^([^=]*)=(.*)/;
		if ($name eq 'client_address') {
			$ip = $value;
			print STDERR "ip is $ip\n" if $debug;
		}
		elsif ($name eq 'sender') {
			$mailFrom = $value;
			print STDERR "mailFrom is $mailFrom\n" if $debug;
		}
		elsif ($name eq 'recipient') {
			$rcptTo = $value;
			print STDERR "rcptTo is $rcptTo\n" if $debug;
		}
		elsif ($name eq 'helo_name') {
			$helo = $value;
			print STDERR "helo is $helo\n" if $debug;
		}
	}

	my $retries = 0;
	my $action;
	my $retry;
	my $status;
	while ($retries < 2) {
		($action, $retry, $status) = performChecks($dbh, $retries, $ip,
			$mailFrom, $rcptTo, $helo);
		last unless $retry;
		$retries++;
		sleep 10;
	}
		
	if ($status) {
		$status =~ tr/\n/_/;
		print "action=451 $status\n\n";
		print STDERR "action=451 $status\n\n" if $debug;
	}
	else {
		print "action=$action\n\n";
		print STDERR "action=$action\n\n" if $debug;
	}
}

sub performChecks
{
	my ($dbh, $attempt, $ip, $mailFrom, $rcptTo, $helo) = @_;

	my $action;
	eval {
		if ($attempt == 0) {
#			$dbh->do('LOCK TABLE greylist IN ACCESS EXCLUSIVE MODE');
			$dbh->do('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
		}

		$action = updateDB($dbh, $ip, $mailFrom, $rcptTo, $helo);
	}; 

	my $status = $@;
	if ($status) {
		$dbh->rollback;
		return (undef, 1, $status);
	}
	else {
		$dbh->commit;
		return $action;
	}
}

sub updateDB
{
	my ($dbh, $ip, $mailFrom, $rcptTo, $helo) = @_;

	my $logSth = $dbh->prepare(
		'INSERT INTO logs (ip_address, mail_from, rcpt_to, helo, created)
			VALUES (?, ?, ?, ?, NOW())');
	$logSth->execute($ip, $mailFrom, $rcptTo, $helo);

	# Check if the sender or recipient address is whitelisted.
	my $isWhitelisted = checkWhitelist($dbh, $mailFrom, $rcptTo);

	# Update the greylist table. We do this even if the sender or recipient
	# addresses have been whitelisted to ensure that the greylist table is
	# populated for those addresses. This allows greylisting to be enabled in
	# the future for those addresses without causing any delay in the
	# acceptance of mail.
	my $greylistStatus = checkGreylist($dbh, $ip, $mailFrom, $rcptTo);

	# The whitelist status takes precedence over the greylist status.
	return $isWhitelisted || $greylistStatus;
}

sub checkWhitelist
{
	my ($dbh, $mailFrom, $rcptTo) = @_;

	my $sth = $dbh->prepare(
		'SELECT c.mail_from FROM user_addresses AS a JOIN
			whitelist_from AS b ON a.user_id = b.user_id JOIN
			mail_from_addresses AS c ON c.id = b.mail_from_id
			WHERE a.address = ?');
	$sth->execute($rcptTo);
	my $row;
	while ($row = $sth->fetchrow_arrayref) {
		return ACCEPTED if acceptAddress($mailFrom, $row->[0]);
	}

	# Check if the recipient address is whitelisted.
	$sth = $dbh->prepare(
		'SELECT rcpt_to FROM whitelist_to WHERE NOT filter_greylist');
	$sth->execute;
	while ($row = $sth->fetchrow_arrayref) {
		return ACCEPTED if acceptAddress($rcptTo, $row->[0]);
	}

	return undef;
}

sub checkGreylist
{
	my ($dbh, $ip, $mailFrom, $rcptTo) = @_;

	# Check if the tuple has been seen before.
	my $sth = $dbh->prepare(
		q(SELECT id,
			CASE NOW() - created > INTERVAL '1 hour'
				WHEN TRUE THEN 1
				ELSE 0
			END
			FROM greylist WHERE ip_address = ? AND mail_from = ? AND
				rcpt_to = ?));
	$sth->execute($ip, $mailFrom, $rcptTo);
	my ($id, $expired) = $sth->fetchrow_array;

	# Special case for certain domains. The retries do not always come from
	# the same server, but they all seem to be within the same class C network.
	if (!defined($id)) {
		my ($domain) = $mailFrom =~ /\@(.*)$/;
		$sth = $dbh->prepare(
			'SELECT COUNT(*) FROM classc_domains WHERE domain = ?');
		$sth->execute($domain);
		my $row = $sth->fetchrow_arrayref;
		if ($row->[0]) {
			$sth = $dbh->prepare(
				q(SELECT id,
					CASE NOW() - created > INTERVAL '1 hour'
						WHEN TRUE THEN 1
						ELSE 0
					END
					FROM greylist
					WHERE SUBSTRING(ip_address FROM '^[0-9]+\.[0-9]+\.[0-9]+')
						= ?
					AND mail_from = ? AND rcpt_to = ?));
			my ($network) = $ip =~ /^([0-9]+\.[0-9]+\.[0-9]+)/;
			$sth->execute($network, $mailFrom, $rcptTo);
			($id, $expired) = $sth->fetchrow_array;
		}
	}

	if (defined($id) && $expired) {
		$sth = $dbh->prepare(
			'UPDATE greylist SET modified = NOW(), successful = successful + 1
				WHERE id = ?');
		$sth->execute($id);
		return ACCEPTED;
	}
	elsif (defined($id)) {
		$sth = $dbh->prepare(
			'UPDATE greylist SET modified = NOW(),
				unsuccessful = unsuccessful + 1
				WHERE id = ?');
		$sth->execute($id);
		return REJECTED;
	}
	else {
		$sth = $dbh->prepare(
			'INSERT INTO greylist
				(ip_address, mail_from, rcpt_to, created, unsuccessful)
				VALUES (?, ?, ?, NOW(), 1)');
		$sth->execute($ip, $mailFrom, $rcptTo);
		return REJECTED;
	}
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
