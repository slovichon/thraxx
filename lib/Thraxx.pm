# Thraxx - universal login library - core routines
# $Id$
package Thraxx;

use DBH qw(:all);
use strict;

our $VERSION = 0.1;

use constant E_NONE => 0;

use constant TRUE  => 1;
use constant FALSE => 0;

sub new
{
	my $class = shift;
	my %prefs = (
		wasp  => WASP->new(),
	);

	# Fill up %prefs
	delete $INC{"babs-config.inc"} if exists $INC{"babs-config.inc"};
	require "babs-config.inc";

	# Initialize DBH
	{
		my %args = (wasp => $prefs{wasp});
		my %map = (
			host		=> "dbh_host",
			username	=> "dbh_username",
			password	=> "dbh_password",
			database	=> "dbh_database",
		);
		# These settings are optional; only pass them
		# to DBH::new() if they are specified.
		my ($k, $v);
		while (($k, $v) = each %map)
		{
			$args{$k} = $prefs{$v} if exists $prefs{$v};
		}
		$prefs{dbh} = &{$prefs{dbh_type}}(
				*{$prefs{dbh_type}}{PACKAGE}, %args);
	}

	return construct($class, %prefs);
}

sub construct
{
	my ($class, %prefs) = @_;

	# Error-check our environment
	die("No WASP object specified")	unless $prefs{wasp};
	$prefs{wasp}->throw("No DBH specified")		unless $prefs{dbh};

	# Strict-preference setting
	tie %prefs, 'Thrax::Prefs', %prefs;

	# This should fill up %prefs
	delete $INC{"babs-config.inc"} if exists $INC{"babs-config.inc"};
	require "babs-config.inc";


	return $this;
}

sub throw
{
	my ($this) = shift;
	my $msg = "Thraxx error: " . join '', @_;

	$this->{wasp}->throw($msg);
}

require "crypt.inc";
require "misc.inc";
require "sessions.inc";
require "users.inc";

package Thrax::Prefs;

sub TIEHASH
{
	my ($class, %prefs) = @_;
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
