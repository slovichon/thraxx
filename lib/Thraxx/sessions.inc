# Thraxx session routines
# $Id$
use strict;

use constant SESSION_MULT_ALLOW		=> 1;
use constant SESSION_MULT_DISALLOW	=> 2;
use constant SESSION_MULT_CLEAR		=> 3;

use constant E_SESSION_EXIST => (001<<5); # Non-existant session

# Front-runner
sub session_auth
{
}

sub session_create
{
	my ($this, $user_id) = @_;
	return E_USER_EXIST() unless $this->user_exists($user_id);
	my $id = $this->__gen_key();
	$this->{dbh}->query("	INSERT INTO
					thraxx_sessions
				(
					user_id,
					session_key
				) VALUES (
					$user_id,
					'$id'
				)", DB_NULL);
	return $this->{dbh}->last_insert_id;
}

sub __gen_key
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
	return E_SESSION_EXIST unless $this->session_exists($id);
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
