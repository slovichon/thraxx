# Thraxx error-message routines
# $Id$

sub err_lookup
{
	my ($this, $err) = @_;
	my %msgs = (
		E_NONE()		=> "No error",
		E_SESSION_EXIST()	=> "Non-existant session, or session already exists",
		E_USER_EXIST()		=> "Non-existant user, or user already exists",
		E_USER_PASSWORD()	=> "Invalid user password",
		E_USER_USERNAME()	=> "Invalid user username",
		E_USER_MISC()		=> "Miscellaneous error",
	);
	return "Undefined error type" unless exists $msgs{$err};
	return $msgs{$err};
}

return TRUE();
