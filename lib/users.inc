# users.inc - Thraxx user routines
# $Id$

use constant E_USER_EXIST => (001<<0); # Non-existant user

sub user_add
{
	my ($this, $user) = @_;
	my $password = $this->{dbh}->prepare_str($user->{password}, SQL_REG);
	$this->{dbh}->query("	INSERT INTO
					thraxx_users
				(
					password
				) VALUES (
					'$password'
				)", DB_NULL);
}

sub user_update
{
	my ($this, $user) = @_;
	return E_USER_EXIST unless $this->user_exists($user->{user_id});
	my $password = $this->{dbh}->prepare_str($user->{password}, SQL_REG);
	$this->{dbh}->query("	UPDATE
					thraxx_users
				SET
					password = '$password'
				WHERE
					user_id = $user->{user_id}", DB_NULL);
	return E_NONE;
}

sub user_remove
{
	my ($this, $user_id) = @_;
	return E_USER_EXIST unless $this->user_exists($user_id);
	$this->{dbh}->query("	DELETE FROM
					thraxx_users
				WHERE
					user_id = $user_id", DB_NULL);

	return E_NONE;
}

sub user_exists
{
	my ($this, $user_id) = @_;
	return FALSE unless defined $user_id && $user_id =~ /^\d+$/;
	return $this->{dbh}->query("	SELECT
					user_id
				FROM
					thraxx_users
				WHERE
					user_id = $user_id", DB_COL);
}

return 1;
