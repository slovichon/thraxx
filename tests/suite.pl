#!/usr/bin/perl -W

use strict;
use Thraxx;
use WASP;

sub ok()
{
	print "\033[1;0;32mTest succeeded\033[1;0;0m\n\n";
}

sub fail()
{
	print "\033[1;0;31mTest failed!\033[1;0;0m\n\n";
	die;
}

sub princ
{
	print "\033[1;0;34m", @_, ":\033[1;0;0m\n";
}

my $w = WASP->new;
$w->die(1);
#my $d = DBH->new();
my $t = Thraxx->construct(wasp=>$w, dbh=>1, skip_init=>1);

########################################################################
# crypt.inc
princ "Random alphanumeric characters";
eval {
print $t->rand_str(25, Thraxx::RAND_VIS_ALNUM), "\n"	for 1 .. 3; 1
}; $@ ? fail : ok;

princ "Random non-quote characters";
eval {
print $t->rand_str(25, Thraxx::RAND_VIS_NQ), "\n"	for 1 .. 3;
}; $@ ? fail : ok;

my $key;

princ "Generating keys";
eval {
for (1 .. 3)
{
	print q[];
	foreach my $type (Thraxx::CRYPT_DES, Thraxx::CRYPT_MD5,
		Thraxx::CRYPT_EXT_DES, Thraxx::CRYPT_BLOWFISH)
	{
		$key = $t->gen_key($type);
		print "[type $type]: $key\n";
	}
}
}; $@ ? fail : ok;

$t->{crypt_key} = $key;

my $data = $t->rand_str(40, Thraxx::RAND_VIS_ALNUM);
my $enc = $t->crypt($data);

princ "Encrypting data";
print "data: $data\nenc:  $enc\n";

my $copy = $data;
my $enc2 = $t->crypt($copy);

print "copy: $copy\nenc2: $enc2\n";

$enc eq $enc2 ? ok : fail;

########################################################################
# isr.inc

# isr_check_field() will be tested heavily by write_config()

########################################################################
# misc.inc

princ "in_array()";
print "5 in (", 2..7, ") and 1 not in (", 2..7 ,")\n";
Thraxx::in_array(5, [2 .. 7]) && !Thraxx::in_array(1, [2 .. 7]) ? ok : fail;

princ "slurp_file()";

my $s="this
is
my
favorite string";

{
my $_t = $s;
$_t =~ s/\n/\\n/g;
printf "Writing to file: $_t\n";
}

open OUT, "> out";
print OUT $s;
close OUT;

my $p = $t->slurp_file("out");
{
my $_t = $p;
$_t =~ s/\n/\\n/g;
print "Reading from file: $_t\n";
}
$s eq $p ? ok : fail;

princ "write_config()";
eval {
$t->write_config;
}; $@ ? fail : ok;

# Skip flatten*

########################################################################
# users.inc

#my $uid = $t->user_add(password=>"hi there");


########################################################################
# sessions.inc

#my $sid = $t->session_create($uid);


########################################################################
# udf.inc






exit 0;
