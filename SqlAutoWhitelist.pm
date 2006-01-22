package SqlAutoWhitelist;

use strict;

use DBI;
use Mail::SpamAssassin::PersistentAddrList;

our @ISA = qw(Mail::SpamAssassin::PersistentAddrList);

# Constructor - stores a database handle that will be used to persist the
# whitelist addresses.
sub new
{
	my ($class, $dbh) = @_;

	my $type = ref($class) || $class;
	my $obj = $type->SUPER::new();
	$obj->{dbh} = $dbh;

	return $obj;
}

# Returns the database handle.
sub getDbHandle
{
	my $self = shift;

	return $self->{dbh};
}

# Creates a new checker object. The checker object encapsulates a connection to
# the database.
sub new_checker
{
	my $factory = shift;

	my $checker = {};
	bless $checker, ref($factory);
	$checker->{dbh} = $factory->{dbh};

	return $checker;
}

# Returns a hashref containing the scores for a given email address.
sub get_addr_entry
{
	my ($self, $addr) = @_;

	# Make sure that the email address has been converted to lowercase.
	$addr = lc $addr;

	# Extract the record from the database, and return a hashref of the total
	# score and number of times that the address has been encountered. If no
	# rows are retrieved from the database, then this is a new email address
	# and we return an appropriately initialised hashref.
	my ($address, $ip) = $addr =~ /^(.*)\|ip=(.*)$/;
	my $sth = $self->{dbh}->prepare(
		'SELECT score, count, created FROM auto_whitelist
			WHERE address = ? AND ip = ?');

	$sth->execute($address, $ip);
	my $row = $sth->fetchrow_arrayref;

	my $entry;
	if ($row) {
		$entry = { addr => $addr, address => $address, ip => $ip,
			totscore => $row->[0], count => $row->[1], created => $row->[2] };
	}
	else {
		$entry = { addr => $addr, address => $address, ip => $ip,
			totscore => 0, count => 0 };
	}

	return $entry;
}

sub add_score
{
	my ($self, $entry, $score) = @_;

	$entry->{totscore} += $score;
	$entry->{count}++;
	if ($entry->{count} != 1) {
		# Update the entry. However, the entry may have been removed if its
		# address did not originally contain an IP address, in which case we
		# will need to recreate the entry.
		my $numRows = $self->_updateEntry($entry);
		if ($numRows == 0) {
			($entry->{address}, $entry->{ip}) =
				$entry->{addr} =~ /^(.*)\|ip=(.*)$/;
			$self->_insertEntry($entry, 1);
		}
	}
	else {
		$self->_insertEntry($entry, 0);
	}

	return $entry;
}

sub _updateEntry
{
	my ($self, $entry) = @_;

	my $sth = $self->{dbh}->prepare(
		'UPDATE auto_whitelist SET score = ?, count = ?
			WHERE address = ? AND ip = ?');
	return $sth->execute($entry->{totscore}, $entry->{count},
		$entry->{address}, $entry->{ip});
}

sub _insertEntry
{
	my ($self, $entry, $writeCreated) = @_;

	my $sth;
	if ($writeCreated) {
		$sth = $self->{dbh}->prepare(
			'INSERT INTO auto_whitelist (score, count, address, ip, created)
				VALUES (?, ?, ?, ?, ?)');
		$sth->execute($entry->{totscore}, $entry->{count}, $entry->{address},
			$entry->{ip}, $entry->{created});
	}
	else {
		$sth = $self->{dbh}->prepare(
			'INSERT INTO auto_whitelist (score, count, address, ip)
				VALUES (?, ?, ?, ?)');
		$sth->execute($entry->{totscore}, $entry->{count}, $entry->{address},
			$entry->{ip});
	}
}

sub remove_entry
{
	my ($self, $entry) = @_;

	my $sth = $self->{dbh}->prepare(
		'DELETE FROM auto_whitelist WHERE address = ? AND ip = ?');
	$sth->execute($entry->{address}, $entry->{ip});
}

sub finish
{
	# Nothing to do here - the database connection will be closed by the main
	# driving script.
	return;
}

1;
