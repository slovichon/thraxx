#!/usr/bin/perl -W

use strict;
use Thraxx;
use WASP;
use DBH qw(:all);
use DBH::MySQL;



sub _ {
	if ($_[0]) {
		print "\033[1;40;32mTest succeeded\033[1;0;0m\n\n";
	} else {
		print "\033[1;40;31mTest failed!\033[1;0;0m\n\n";
		die;
	}
}

sub test {
	print "\033[1;40;34m", @_, ":\033[1;0;0m\n";
}

my $w = WASP->new;
$w->die(1);
my $d = DBH::MySQL->new(host=>"12.226.98.118", username=>"thraxx",
		password=>"lNBDOD92Pec", database=>"thraxx",
		wasp=>$w);
my $t = Thraxx->construct(wasp=>$w, dbh=>$d, skip_init=>1);

my ($s, $p, $i, $j, $k);

########################################################################
# crypt.inc
test "Random alphanumeric characters";
eval {
print $t->rand_str(25, Thraxx::RAND_VIS_ALNUM), "\n"	for 1 .. 3;
};
_ !$@;

test "Random non-quote characters";
eval {
print $t->rand_str(25, Thraxx::RAND_VIS_NQ), "\n"	for 1 .. 3;
};
_ !$@;

my $key;

test "Generating keys";
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
};
_ $@;

$t->{crypt_key} = $key;

my $data = $t->rand_str(40, Thraxx::RAND_VIS_ALNUM);
my $enc = $t->crypt($data);

test "Encrypting data";
print "data: $data\nenc:  $enc\n";

my $copy = $data;
my $enc2 = $t->crypt($copy);

print "copy: $copy\nenc2: $enc2\n";

_ $enc eq $enc2;

########################################################################
# isr.inc

# isr_check_field() will be tested heavily by write_config()

########################################################################
# misc.inc

test "in_array()";
print "5 in (", 2..7, ") and 1 not in (", 2..7 ,")\n";
_ Thraxx::in_array(5, [2 .. 7]) && !Thraxx::in_array(1, [2 .. 7]);

test "in_hash()";
print "5 in (a=>1, b=>5) and 1 not in (a=>6, b=>2, c=>7)\n";
_ Thraxx::in_hash(5, {a=>1, b=>5}) && !Thraxx::in_hash(1, {a=>6, b=>2, c=>7});

test "slurp_file()";
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
_ $s eq $p;

test "write_config()";
eval {
$t->write_config;
};
_ !$@;

# Skip flatten*

########################################################################
# users.inc

test "Creating user";
my ($err, $uerr) = $t->user_add({password=>"hi there"});
my $user_id = $d->last_insert_id;
print "Errors: $err\nUser errors: @$uerr\nUser ID: $user_id\n";
_ $err == Thraxx::E_NONE() && @$uerr == 0;

test "Changing password";
($err, $uerr) = $t->user_update({user_id=>$user_id, password=>"new pass"});
print "Errors: $err\nUser errors: @$uerr\n";
_ $err == Thraxx::E_NONE() && @$uerr == 0;

test "user_exists()";
_ $t->user_exists($user_id);
_ $t->user_exists(-1);
_ $t->user_exists(5);

test "user_auth()";
_ !$t->user_auth($user_id, "new pass");
_ $t->user_auth($user_id, "bad pass");

########################################################################
# str.inc

test "encode_html()";
$s = qq!<html>my "string" & is here</html>!;
$p = $t->encode_html($s);
$k = qq!&lt;html&gt;my &quot;string&quot; &amp; is here&lt;/html&gt;!;
print "string: $s\n";
print "encoded: $p\n";
_ $p eq $k;

# str_parse(), oh boy

########################################################################
# sessions.inc

test "Creating session";
my $session = $t->session_create($user_id);
print "Session ID: $session->{session_id}\nSession key: $session->{session_key}\n";
_ ref $session eq "HASH";

test "Session size";
_ length($session->{session_key}) == Thraxx::SESSION_KEY_LEN();

test "session_exists()";
_ $t->session_exists($session->{session_id});

test "Removing session";
_ !$t->session_remove($session->{session_id});

test "Removing user";
_ !$t->user_remove($user_id);

########################################################################
# udf.inc
# Note: this will be tested with custom fields
# in users.inc and sessions.inc tests.

exit 0;
