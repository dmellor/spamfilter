#!/usr/bin/perl

use strict;

use Config::IniFiles;
use DBI;

use constant ACCEPTED => 0;
use constant REJECTED => 1;

main();

sub main
{
	my $home = $ENV{SPAMFILTER_HOME};
	my $cfg = new Config::IniFiles(-file => "$home/spamfilter.ini");
	my $dsn = $cfg->val('Greylist', 'dsn');
	my $user = $cfg->val('Greylist', 'user');
	my $password = $cfg->val('Greylist', 'password');
	my $dbh = DBI->connect($dsn, $user, $password,
		{ PrintError => 0, RaiseError => 1, AutoCommit => 0 });

	my $returnCode;
	eval { $returnCode = checkGreylist($dbh) };
	my $status = $@;
	if ($status) {
		$dbh->rollback;
		$dbh->disconnect;
		exit REJECTED;
	}
	else {
		$dbh->commit;
		$dbh->disconnect;
		exit $returnCode;
	}
}

sub checkGreylist
{
	my $dbh = shift;

	my $ip = $ENV{TCPREMOTEIP};
	my $mailFrom = lc $ENV{MAILFROM};
	my $rcptTo = lc $ENV{RCPTTO};

	$dbh->do('LOCK TABLE greylist IN ACCESS EXCLUSIVE MODE');

	my $logSth = $dbh->prepare(
		'INSERT INTO logs (ip_address, mail_from, rcpt_to, created)
			VALUES (?, ?, ?, NOW())');
	$logSth->execute($ip, $mailFrom, $rcptTo);

	# Check if the sender address is whitelisted.
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
	$sth = $dbh->prepare('SELECT rcpt_to FROM whitelist_to');
	$sth->execute;
	while ($row = $sth->fetchrow_arrayref) {
		return ACCEPTED if acceptAddress($rcptTo, $row->[0]);
	}

	# Check if the tuple has been seen before.
	$sth = $dbh->prepare(
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
		$row = $sth->fetchrow_arrayref;
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
