# Thraxx user routines
# $Id$

use strict;

sub _user_init
{
	my ($this) = @_;
	my $g = $this->{error_const_group};

	# Error constants
	$g->add("E_USER_EXIST");	# Non-existant user

	$g->add("E_USER_PASS");		# Bad password
}

sub user_add
{
	my ($this, $user) = @_;
	my $dbh = $this->{dbh};
	my $err = E_NONE();
	# Validate data
	$err |= E_USER_PASS() unless $user->{password};
	# Validate/Prepare user-defined fields data
	my $uerr = $this->udf_validate(FLD_USER(), $user);
	return ($err, $uerr) if $err != E_NONE() || @$uerr;
	# Prepare data
	my $password = $dbh->prepare_str($user->{password}, SQL_REG);
	my $sql_fields = "";
	my $sql_values = "";
	my ($field_id);
	while (($field_id) = each %{ $this->{user_fields} })
	{
		$sql_fields .= " $field_id, ";
		$sql_values .= " '$user->{$field_id}', ";
	}
	$dbh->query("	INSERT INTO
				thraxx_users
			(
				$sql_fields
				password
			) VALUES (
				$sql_values
				'$password'
			)", DB_NULL);
	return (E_NONE(), []);
}

sub user_update
{
	my ($this, $user) = @_;
	my $dbh = $this->{dbh};
	return (E_USER_EXIST(), []) unless $this->user_exists($user->{user_id});
	my $err = E_NONE();
	# Validate data
	$err |= E_USER_PASS() unless $user->{password};
	# Validate/Prepare user-defined fields data
	my $uerr = $this->udf_validate(FLD_USER(), $user);
	return ($err, $uerr) if $err != E_NONE() or @$uerr;
	# Prepare data
	my $password = $dbh->prepare_str($user->{password}, SQL_REG);
	my $ufields = "";
	my ($field_id);
	while (($field_id) = each %{ $this->{user_fields} })
	{
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

sub user_remove
{
	my ($this, $user_id) = @_;
	return E_USER_EXIST() unless $this->user_exists($user_id);
	$this->{dbh}->query("	DELETE FROM
					thraxx_users
				WHERE
					user_id = $user_id", DB_NULL);

	return E_NONE();
}

sub user_exists
{
	my ($this, $user_id) = @_;
	return FALSE() unless $user_id && $user_id =~ /^\d+$/;
	return $this->{dbh}->query("	SELECT
					user_id
				FROM
					thraxx_users
				WHERE
					user_id = $user_id", DB_COL);
}

sub user_auth
{
	my ($this, $user_id, $password) = @_;
	return E_USER_EXIST() unless $this->user_exists($user_id);
	my $dbh = $this->{dbh};
	$password = $dbh->prepare_str($this->crypt($password), SQL_REG);
	my $ret = $dbh->query("	SELECT
					user_id
				FROM
					thraxx_users
				WHERE
					user_id = $user_id
				AND	password = '$password' ", DB_COL);
	return E_USER_PASS() unless $ret;
	return E_NONE();
}

return TRUE();
