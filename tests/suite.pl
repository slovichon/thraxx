#!/usr/bin/perl -W

use strict;
use Thraxx;
use WASP;

my $w = WASP->new;
$w->display(1);
#my $d = DBH->new();
my $t = Thraxx->construct(wasp=>$w, dbh=>1, skip_init=>1);

$\ = "\n";

########################################################################
# crypt.inc
print "Random alphanumeric characters: ";
print $t->rand_str(25, Thraxx::RAND_VIS_ALNUM)	for 1 .. 3;

print "\nRandom non-quote characters: ";
print $t->rand_str(25, Thraxx::RAND_VIS_NQ)	for 1 .. 3;

my $key;

for (1 .. 3)
{
	print q[];
	foreach my $type (Thraxx::CRYPT_DES, Thraxx::CRYPT_MD5,
		Thraxx::CRYPT_EXT_DES, Thraxx::CRYPT_BLOWFISH)
	{
		$key = $t->gen_key($type);
		print "Generated key[$type]: $key";
	}
}

my $data = $t->rand_str(40, Thraxx::RAND_VIS_ALNUM);
my $enc = $t->crypt($data);

print "\nEncrypting data ($data): $enc";
########################################################################
# isr.inc


########################################################################
# misc.inc

print "In array"	if	Thraxx::in_array(5, [2 .. 7]);
print "Not in array"	unless	Thraxx::in_array(1, [2 .. 7]);

my $s="this
is
my
favorite string";

print "Writing string ($s) to file";

open OUT, "> out";
print OUT $s;
close OUT;

print "Retrieving file contents: ", $t->slurp_file("out");

$t->write_config;
print "Config saved";

# Skip flatten*

########################################################################
# users.inc

my $uid = $t->user_add();


########################################################################
# sessions.inc

my $sid = $t->session_create($uid);


########################################################################
# udf.inc






exit 0;
