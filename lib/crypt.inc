# Thraxx crypto routines
# $Id$

use constant RAND_VIS_NQ => 1;
use constant RAND_VIS_ALNUM => 2;

sub crypt
{
	my ($this, $data) = @_;
	return crypt($data, $this->{crypt_key});
}

sub rand_str
{
	my ($this, $size, $type) = @_;
	$type = RAND_VIS_NQ unless defined $type;
	my ($min, $max, @excluded);
	if ($type == RAND_VIS_NQ)
	{
		$min = 33;
		$max = 126;
		@excluded = (34, 39, 92); # ' " \
	} elsif ($type == RAND_VIS_ALNUM) { # Just alphanumerics
		$min = 47;
		$max = 122;
		@excluded = (58 .. 64, 91 .. 96);
	} else {
		$this->throw("Invalid type; type: $type");
	}

	my $str = "";
	my $ch = "";

	for (1 .. $size)
	{
		do {
			$ch = $min + int rand($max-$min+1);
		} while (in_array($ch, \@excluded));
		$str .= chr($ch);
	}

	return $str;
}

return 1;
