# Thraxx internal structure representation routines
# $Id$

use DBH qw(:all);
use strict;

use constant ISR_TYPE_STR => 1;
use constant ISR_TYPE_NUM => 2;

sub isr_check_field
{
	my ($this, $table, $field, $op, $val) = @_;

	my $num = sub { $_[0] && $_[0] =~ /^\d+$/ ? $_[0] : 0 };

	my %ops = {
		ISR_TYPE_NUM()	=> {
			'='	=> $num,
			'<'	=> $num, 
			'>'	=> $num,
			'<='	=> $num,
			'>='	=> $num,
			'<>'	=> $num,
		},
		ISR_TYPE_STR()	=> {
			'LIKE'	=> sub { q(') . $this->{dbh}->prepare_str($_[0], SQL_WILD) . q(') },
			'='	=> sub { q(') . $this->{dbh}->prepare_str($_[0], SQL_REG)  . q(') },
		},
	};

	my %fields = (
		thraxx_users => {
			user_id		=> ISR_TYPE_NUM,
			password	=> ISR_TYPE_STR,
		},
		thraxx_sessions => {
			session_id	=> ISR_TYPE_NUM,
			user_id		=> ISR_TYPE_NUM,
			session_key	=> ISR_TYPE_STR,
			act_ts		=> ISR_TYPE_NUM,
			create_date	=> ISR_TYPE_NUM,
		},
	);

	return undef unless exists $fields{$table};
	return undef unless exists $fields{$table}{$field};
	return undef unless in_array($op, [ keys %{ $ops{$fields{$table}{$field}} } ]);
	return $ops{$fields{$table}{$field}}{$op}->($val);
}

return TRUE();
