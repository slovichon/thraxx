# Thraxx session routines
# $Id$

use strict;

use constant SESSION_MULT_ALLOW		=> 1;
use constant SESSION_MULT_DISALLOW	=> 2;
use constant SESSION_MULT_CLEAR		=> 3;

sub _session_init
{
	my ($this) = @_;
	my $g = $this->{error_const_group};

	# Error constants
	$g->add("E_SESSION_EXIST"); # Non-existant session
}

# Front-runner
sub session_auth
{
	my ($this, $user_id, $password) = @_;

	# Check for concurrent sessions
	if (my @sessions = $this->session_search)
	{
		if ($this->{simult_sessions} == SESSION_MULT_ALLOW)
		{
			my $ret = $this->user_auth($user_id, $password);
			return $ret if $ret != E_NONE();
			return $this->session_create($user_id);
		} elsif ($this->{simult_sessions} == SESSION_MULT_CLEAR) {
			foreach my $session (@sessions)
			{
# XXX: change to DELETE ... WHERE id = a or id = b or id = c ...
				$this->session_remove($session->{id});
			}
			my $ret = $this->user_auth($user_id, $password);
			return $ret if $ret != E_NONE();
			return $this->session_create($user_id);
		} elsif ($this->{simult_sessions} == SESSION_MULT_DISALLOW) {
			return E_SESSION_EXIST();
		} else {
			$this->throw("Unknown action for handling simultaneous logons; " .
					"action: $this->{simult_sessions}");
		}
	} else {
		my $ret = $this->user_auth($user_id, $password);
		return $ret if $ret != E_NONE();
		return $this->session_create($user_id);
	}
}

sub session_create
{
	my ($this, $user_id) = @_;
	return E_USER_EXIST() unless $this->user_exists($user_id);
	my $dbh = $this->{dbh};
	my $key = $this->_session_gen_key();
	my $esc_key = $dbh->prepare_str($key, SQL_REG);
	$dbh->query("	INSERT INTO
				thraxx_sessions
			(
				user_id,
				session_key
			) VALUES (
				$user_id,
				'$esc_key'
			)", DB_NULL);
	return {
			session_id => $dbh->last_insert_id,
			session_key => $key,
		};
}

sub _session_gen_key
{
	my ($this) = @_;
	my $size = SESSION_KEY_LEN();
	my $id;
	# Make sure the session identifier doesn't already exist
	do {
		$id = $this->random_str($size, RAND_VIS_ALNUM());
	} while ($this->session_exists($id));
	return $id;
}

sub session_remove
{
	my ($this, $id) = @_;
	return E_SESSION_EXIST() unless $this->session_exists($id);
	$id = $this->{dbh}->prepare_str($id, SQL_REG);
	$this->{dbh}->query("	DELETE FROM
					thraxx_sessions
				WHERE
					session_id = '$id'", DB_NULL);
}

sub session_search
{
	my ($this, @rules) = @_;

	# Build SQL
	my $sql = "	SELECT
				*
			FROM
				thraxx_sessions ";
	
	if (@rules)
	{
		$sql .= " WHERE ";
		my ($spec, @ands, $group, $val);
		foreach $spec (@rules)
		{
			$group = $spec->{group} || 0;
			$group = 0 unless $group =~ /^\d+$/;

			$val = $this->isr_check_field("thraxx_sessions",
				$spec->{field}, $spec->{op}, $spec->{value});

			if (defined $val)
			{
				if ($ands[$group])
				{
					$ands[$group] .= " AND ";
				} else {
					$ands[$group] = "";
				}
				$ands[$group] .= " $spec->{field} $spec->{op} $val ";
			}
		}
		$sql .= " ( " . join(" ) OR (", @ands) . " ) ";
	}
	
	my @sessions = ();
	$this->{dbh}->query($sql, DB_ROWS);
	my %session;
	push @sessions, \%session while %session = $this->{dbh}->fetch_row;
	return \@sessions;
}

# sub session_exists
# {
#	my ($this, $id) = @_;
#	return $this->session_search(session_id=>$id);
# }

sub session_exists
{
	my ($this, $id) = @_;
	my $size = SESSION_KEY_LEN();
	return FALSE unless $id =~ /^[a-zA-Z0-9]{$size}$/;
	return $this->{dbh}->query("	SELECT
						session_id
					FROM
						thraxx_sessions
					WHERE
						session_id = '$id'", DB_COL);
}

# sub sessions
# {
#	my ($this) = @_;
#	return $this->session_search();
# }

sub sessions
{
	my ($this) = @_;
	my $dbh = $this->{dbh};
	$dbh->query("	SELECT
				*
			FROM
				thraxx_sessions", DB_ROWS);
}

return TRUE();
