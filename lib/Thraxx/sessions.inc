# Thraxx session routines
# $Id$

use DBH qw(:all);
use strict;

use constant SESSION_MULT_ALLOW		=> 1;
use constant SESSION_MULT_DISALLOW	=> 2;
use constant SESSION_MULT_CLEAR		=> 3;

sub _session_init {
	my ($this) = @_;
	my $g = $this->{error_const_group};

	# Error constants
	$g->add("E_SESSION_EXIST"); # Non-existant session

	# Purge old sessions
	$this->{dbh}->query("	DELETE FROM
					thraxx_sessions
				WHERE
					act_ts > $this->{timeout}", DB_NULL);
}

# Front-runner
sub session_auth {
	my ($this, $user_id, $password) = @_;

	# Check for concurrent sessions
	if (my @sessions = $this->session_search(
		criteria => [[{	field 	=> "user_id",
				op 	=> "=",
				value 	=> $user_id }]])) {
		if ($this->{simult_sessions} == SESSION_MULT_ALLOW) {
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

sub session_create {
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

sub _session_gen_key {
	my ($this) = @_;
	my $size = SESSION_KEY_LEN();
	my $id;
	# Make sure the session identifier doesn't already exist
	do {
		$id = $this->rand_str($size, RAND_VIS_ALNUM());
	} while ($this->session_exists($id));
	return $id;
}

sub session_update {
	my ($this, $id) = @_;
	return E_SESSION_EXIST() unless $this->session_exists($id);
	$this->{dbh}->query("	UPDATE
					thraxx_sessions
				SET
					act_ts = 0
				WHERE
					session_id = $id", DB_NULL);
}

sub session_remove {
	my ($this, $id) = @_;
	return E_SESSION_EXIST() unless $this->session_exists($id);
	$id = $this->{dbh}->prepare_str($id, SQL_REG);
	my $ret = $this->{dbh}->query("	DELETE FROM
						thraxx_sessions
					WHERE
						session_id = $id", DB_NULL);
	return $ret ? E_NONE() : E_SESSION_EXIST();
}

# For future extensions with a backwards-compatible
# interface, search criteria should be given as a
# hash element named `criteria' and should contain
# one or more `or' groups. Each `or' group should
# contain one or more `and' group composed of one
# or more criteria fields that must match.
sub session_search {
	my ($this, %prefs) = @_;
	# Build database query
	my $where = "";
	if (ref $prefs{criteria} eq "ARRAY" && @{ $prefs{criteria} }) {
		$where .= " WHERE ";
		my ($ands, $criteria, $val);
		# foreach `and' group in the `or' groups
		foreach $ands (@{ $prefs{criteria} }) {
			$where .= "(";
			foreach $criteria (@$ands) {
				if (defined($val = $this->isr_check_field(
					"thraxx_sessions", $criteria->{field},
					$criteria->{op}, $criteria->{value}))) {
					$where .= sprintf " %s %s %s AND ",
							$criteria->{field},
							$criteria->{op}, $val;
				}
			}
			$where =~ s/ AND $/) OR /;
		}
		$where =~ s/ OR $//;
	}
	# Query database
	my $dbh = $this->{dbh};
	$dbh->query("	SELECT
				*
			FROM
				thraxx_sessions
			$where ", DB_ROWS);
	my @sessions = ();
	my %session;
	while (%session = $dbh->fetch_row) {
		push @sessions, {%session};
	}
	return \@sessions;
}

# sub session_exists {
#	my ($this, $id) = @_;
#	return $this->session_search(session_id=>$id);
# }

sub session_exists {
	my ($this, $id) = @_;
	return FALSE() unless $id && $id =~ /^\d+$/;
	return $this->{dbh}->query("	SELECT
						session_id
					FROM
						thraxx_sessions
					WHERE
						session_id = $id", DB_COL);
}

# sub sessions {
#	my ($this) = @_;
#	return $this->session_search();
# }

sub sessions {
	my ($this) = @_;
	my $dbh = $this->{dbh};
	return $dbh->query("	SELECT
					*
				FROM
					thraxx_sessions", DB_ROWS);
}

# sub session_get {
#	my ($this, $id) = @_;
#	return $this->session_search(
#		criteria => [[{ field 	=> "session_id",
#				op	=> "=",
#				value	=> $id }]]);
# }

sub session_get {
	my ($this, $id) = @_;
	return E_SESSION_EXIST() unless $this->session_exists($id);
	return $this->{dbh}->query("	SELECT
						*
					FROM
						thraxx_sessions
					WHERE
						id = $id", DB_ROW);
}

return TRUE();
