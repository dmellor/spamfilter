#!/usr/bin/perl

use strict;

use DBI;
use Config::IniFiles;

my $cfg = new Config::IniFiles(-file => '/var/spamfilter/spamfilter.ini');
my $dbh = DBI->connect($cfg->val('AutoWhitelist', 'dsn'),
	$cfg->val('AutoWhitelist', 'user'),
	$cfg->val('AutoWhitelist', 'password'),
	{ PrintError => 0, RaiseError => 1 });

my $sth = $dbh->prepare('SELECT contents FROM saved_mail WHERE id = ?');
my $i = 0;
while (my $id = shift) {
	print "=" x 75, "\n" if $i++;
	$sth->execute($id);
	my ($content) = $sth->fetchrow_array();
	print "$content\n";
}
