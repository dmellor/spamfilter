#!/usr/bin/perl

use strict;
use lib '/var/spamfilter';

use DBI;
#use MySpamAssassin;
use Config::IniFiles;

my $cfg = new Config::IniFiles(-file => '/var/spamfilter/spamfilter.ini');
my $dbh = DBI->connect($cfg->val('AutoWhitelist', 'dsn'),
	$cfg->val('AutoWhitelist', 'user'),
	$cfg->val('AutoWhitelist', 'password'),
	{ PrintError => 0, RaiseError => 1, AutoCommit => 0 });

my $extractStmt = $dbh->prepare(
	'SELECT mail_from, contents FROM saved_mail WHERE id = ?');

my $recipientsStmt = $dbh->prepare(
	'SELECT recipient FROM saved_mail_recipients WHERE saved_mail_id = ?');

my $deleteStmt = $dbh->prepare('DELETE FROM saved_mail WHERE id = ?');

#my $assassin = new MySpamAssassin({ dont_copy_prefs => 1 });
while (my $id = shift) {
	$extractStmt->execute($id);
	my ($from, $message) = $extractStmt->fetchrow_array;
	$extractStmt->finish;
#	my $status = $assassin->check_message_text($message);
#	$status->rewrite_mail;
#	$message = $status->get_full_message_as_text;
	$recipientsStmt->execute($id);
	my $recipients = $recipientsStmt->fetchall_arrayref;
#	$status->finish;
	my $envelope = "F$from\x00";
	foreach my $recipRef (@$recipients) {
		$envelope .= 'T' . $recipRef->[0] . "\x00";
	}

	$envelope .= "\x00";

	my $pid;
	pipe MSGREAD, MSGWRITE;
	pipe ENVREAD, ENVWRITE;
	unless ($pid = fork) {
		defined $pid or die "Could not fork: $!";
		close MSGWRITE;
		close STDIN;
		open STDIN, '<&MSGREAD';
		close MSGREAD;
		close ENVWRITE;
		close STDOUT;
		open STDOUT, '<&ENVREAD';
		close ENVREAD;
		exec '/var/qmail/bin/qmail-queue';
		die "Could not queue mail: $!";
	}

	print MSGWRITE $message;
	close MSGWRITE;
	print ENVWRITE $envelope;
	close ENVWRITE;
	waitpid $pid, 0;
	my $exitStatus = $? >> 8;
	die "Error queuing mail: $exitStatus" if $exitStatus;

	$deleteStmt->execute($id);
}

$dbh->commit;
$dbh->disconnect;
