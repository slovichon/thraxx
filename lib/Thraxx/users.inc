# Thraxx user routines
# $Id$

use DBH qw(:all);
use strict;

sub _user_init {
	my ($this) = @_;
	my $g = $this->{error_const_group};

	# Error constants
	$g->add("E_USER_EXIST");	# Non-existant user

	$g->add("E_USER_PASSWORD");	# Bad password
	$g->add("E_USER_USERNAME");	# Bad username
}

sub user_add {
	my ($this, $user) = @_;
	return E_MISC() unless ref $user eq "HASH";
	my $dbh = $this->{dbh};
	my $err = E_NONE();
	# Validate data
	$err |= E_USER_PASSWORD() unless $user->{password};
	# The username can only consist of a-zA-Z0-9_ so
	# there is no need to SQL-escape it.
	my $username = $user->{username};
#	my $username = $dbh->prepare_str($user->{username}, SQL_REG);
	# We should range from 5 <or minimum> to Thraxx::USERNAME_LEN
	if ($user->{username} =~ /^[a-zA-Z0-9_]{5,}$/) {
		if ($dbh->query("	SELECT
						user_id
					FROM
						thraxx_users
					WHERE
						username = '$username' ", DB_COL)) {
			$err |= E_USER_EXIST()
		}
	} else {
		$err |= E_USER_USERNAME();
	}
	# Validate/Prepare user-defined fields data
	my $uerr = $this->udf_validate(FLD_USER(), $user);
	return ($err, $uerr) if $err != E_NONE() || @$uerr;
	# Prepare data
	my $password = $dbh->prepare_str($this->crypt($user->{password}), SQL_REG);
	my $sql_fields = "";
	my $sql_values = "";
	my ($field_id);
	while (($field_id) = each %{ $this->{user_fields} }) {
		$sql_fields .= " ud_$field_id, ";
		$sql_values .= " '$user->{$field_id}', ";
	}
	$dbh->query("	INSERT INTO
				thraxx_users
			(
				$sql_fields
				password,
				username
			) VALUES (
				$sql_values
				'$password',
				'$username'
			)", DB_NULL);
	return (E_NONE(), []);
}

sub user_update {
	my ($this, $user) = @_;
	return E_MISC() unless ref $user eq "HASH";
	my $dbh = $this->{dbh};
	return (E_USER_EXIST(), []) unless $this->user_exists($user->{user_id});
	my $err = E_NONE();
	# Validate data
	$err |= E_USER_PASSWORD() unless $user->{password};
	# Validate/Prepare user-defined fields data
	my $uerr = $this->udf_validate(FLD_USER(), $user);
	return ($err, $uerr) if $err != E_NONE() or @$uerr;
	# Prepare data
	my $password = $dbh->prepare_str($this->crypt($user->{password}), SQL_REG);
	my $ufields = "";
	my ($field_id);
	while (($field_id) = each %{ $this->{user_fields} }) {
		$ufields .= " ud_$field_id = '$user->{$field_id}', ";
	}
	$dbh->query("	UPDATE
				thraxx_users
			SET
				$ufields
				password = '$password'
			WHERE
				user_id = $user->{user_id}", DB_NULL);
	return (E_NONE(), []);
}

sub user_remove {
	my ($this, $user_id) = @_;
	return E_USER_EXIST() unless $this->user_exists($user_id);
	$this->{dbh}->query("	DELETE FROM
					thraxx_users
				WHERE
					user_id = $user_id", DB_NULL);

	return E_NONE();
}

sub user_exists {
	my ($this) = shift;
	my ($field, $op, $value);
	if (@_ == 1) {
		# Assume user ID
		$field = "user_id";
		$op = "=";
		$value = $_[0];
		return FALSE() unless $value && $value =~ /^\d+$/;
	} else {
		my %spec = @_;
		($field, $op, $value) = @spec{qw(field op value)};
		$value = $this->isr_check_field("thraxx_users", $field, $op, $value);
		return FALSE() unless defined $value;
	}
	return $this->{dbh}->query("	SELECT
						user_id
					FROM
						thraxx_users
					WHERE
						$field $op $value", DB_COL);
}

sub user_auth {
	my ($this, $username, $password) = @_;
	my $enc = $this->crypt($password);
	my $user = $this->user_get(field=>"username", op=>"=", value=>$username);
	return ref $user eq "HASH" && $user->{password} eq $enc;
}

# sub user_get {
#	my ($this, $user_id) = @_;
#	return 	$this->user_search(
#			criteria => [[{ field 	=> user_id,
#					op	=> "=",
#					value 	=> $user_id }]] );
# }

# user_get(field => value)
# user_get(user_id) (defaults to id for single arg)
sub user_get {
	my ($this) = shift;
	my ($field, $op, $value);
	if (@_ == 1) {
		$field = "user_id";
		$op = "=";
		$value = $_[0];
		return E_USER_EXIST() unless $this->user_exists($value);
	} else {
		my %spec = @_;
		($field, $op, $value) = @spec{qw(field op value)};
		$value = $this->isr_check_field("thraxx_users", $field, $op, $value);
		return E_MISC() unless defined $value;
	}
	my %user = $this->{dbh}->query("	SELECT
							*
						FROM
							thraxx_users
						WHERE
							$field $op $value", DB_ROW);
	return %user ? \%user : E_USER_EXIST();
}

sub user_search {
	my ($this, %prefs) = @_;
	# Determine offset
	my $offset = $prefs{offset} || 0;
	$offset = 0 unless $offset =~ /^\d+$/;
	# Determine result limit (check bounds)
	my $limit = $prefs{limit} || 0;
	$limit = 0 unless $limit =~ /^\d+$/;
	$limit = 0 if $limit > $this->{XXX_result_limit};
	if ($limit) {
		# Try user preference
		# Try default preference
	}
	# Build database query
	my $where = "";
	if (ref $prefs{criteria} eq "ARRAY" && @{ $prefs{criteria} }) {
		$where .= " WHERE ";
		my ($ands, $criteria, $val);
		# foreach `and' group in the `or' groups
		foreach $ands (@{ $prefs{criteria} }) {
			$where .= " ( ";
			foreach $criteria (@$ands) {
				if (defined($val = $this->isr_check_field(
					"babs_stories", $criteria->{field},
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
				babs_stories
			$where
			LIMIT
				$limit,
				$offset", DB_ROWS);
	my @stories = ();
	my %story;
	while (%story = $dbh->fetch_row) {
		push @stories, {%story};
	}
	return \@stories;
}

return TRUE();
