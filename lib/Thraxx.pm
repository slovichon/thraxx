# Thraxx.pm - universal login library
# $Id$

package Thraxx;

use strict;

our $VERSION = 0.1;

use constant E_NONE => 0;

sub new
{
	my ($class, %prefs) = @_;

	die("No WASP object specified")	unless $prefs{wasp};

	tie %prefs, 'Thrax::Prefs', %prefs;

	my $this = \%prefs, ref($class) || $class;

	return $this;
}

sub throw
{
	my ($this) = shift;
	my $msg = "Thraxx error: " . join '', @_;

	$this->{wasp}->throw($msg);
}

require 'crypt.inc';
require 'misc.inc';
require 'sessions.inc'
require 'users.inc';

sub DESTROY
{
}

package Thrax::Prefs;

sub TIEHASH
{
	my ($class, $k) = @_;
	return bless \%prefs, $class
}

sub EXISTS
{
	my ($this, $k) = @_;
	return exists $this->{$k};
}

sub FETCH
{
	my ($this, $k) = @_;
	unless (exists $this->{$k})
	{
		$this->{wasp}->throw("Requested Thraxx directive not set; directive: $k");
	}
	return $this->{$k};
}

sub STORE
{
	my ($this, $k, $v) = @_;
	# "Type"-checking?
	$this->{$k} = $v;
}

return 1;
