# misc.inc - Thraxx miscellaneous routines
# $Id$

sub in_array
{
	my ($elem, $arr) = @_;

	for (@$arr)
	{
		return TRUE if $elem == $_;
	}

	return FALSE;
}

return 1;
