package MySpamAssassin;

use strict;

use Mail::SpamAssassin;

our @ISA = qw(Mail::SpamAssassin);

# This class subclasses Mail::SpamAssassin to overcome an annoying feature. If
# a Mail:SpamAssassin object is created and the configuration option
# dont_copy_prefs is set, the init method will still complain in the log file
# about not being able to create the default preferences file. To remove this
# warning we override the create_default_prefs method and have it return true
# if the dont_copy_prefs option is set.

sub create_default_prefs
{
	my($self, $fname, $user, $userdir) = @_;

	return $self->{dont_copy_prefs}
		? 1
		: $self->SUPER::create_default_prefs($fname, $user, $userdir);
}

1;

