# Thraxx crypto routines
# $Id$
use strict;

use constant RAND_VIS_NQ	=> 1;
use constant RAND_VIS_ALNUM	=> 2;

use constant CRYPT_DES		=> 1;
use constant CRYPT_EXT_DES	=> 2;
use constant CRYPT_MD5		=> 3;
use constant CRYPT_BLOWFISH	=> 4;

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

sub gen_key
{
	my ($this, $ktype) = @_;
	my %map = (
		CRYPT_DES()		=> {len=>2,  type=>RAND_VIS_NQ, prefix=>''},
		CRYPT_EXT_DES()		=> {len=>9,  type=>RAND_VIS_NQ, prefix=>''},
		CRYPT_MD5()		=> {len=>12, type=>RAND_VIS_NQ, prefix=>'$1$'},
		CRYPT_BLOWFISH()	=> {len=>22, type=>RAND_VIS_ALNUM, prefix=>'$2a$05$'},
	);
	$this->throw("Invalid key type; type: $ktype") unless exists $map{$ktype};
	return $map{$ktype}{prefix} .
		$this->rand_str($map{$ktype}{len}, $map{$ktype}{type});
}

return TRUE();
