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
	print "\033[1;40;34m", @_, ":\033[1;0;0m\n";
}

my $w = WASP->new;
$w->die(1);
#my $d = DBH->new();
my $t = Thraxx->construct(wasp=>$w, dbh=>1, skip_init=>1);

my ($s, $p, $i, $j, $k);

########################################################################
# crypt.inc
princ "Random alphanumeric characters";
eval {
print $t->rand_str(25, Thraxx::RAND_VIS_ALNUM), "\n"	for 1 .. 3;
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

princ "in_hash()";
print "5 in (a=>1, b=>5) and 1 not in (a=>6, b=>2, c=>7)\n";
Thraxx::in_hash(5, {a=>1, b=>5}) && !Thraxx::in_hash(1, {a=>6, b=>2, c=>7}) ? ok : fail;

princ "slurp_file()";
$s="this \nis\n my \nfavorite string";
$k = $s;
$k =~ s/\n/\\n/g;
printf "Writing to file: $k\n";

open OUT, "> out";
print OUT $s;
close OUT;

$p = $t->slurp_file("out");
$k = $p;
$k =~ s/\n/\\n/g;
print "Reading from file: $k\n";
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
# str.inc

princ "encode_html()";
$s = qq!<html>my "string" & is here</html>!;
$p = $t->encode_html($s);
$k = qq!&lt;html&gt;my &quot;string&quot; &amp; is here&lt;/html&gt;!;
print "string: $s\n";
print "encoded: $p\n";
$p eq $k ? ok : fail;

# str_parse(), oh boy

########################################################################
# sessions.inc

#my $sid = $t->session_create($uid);


########################################################################
# udf.inc






exit 0;
