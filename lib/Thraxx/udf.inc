# Thraxx user-defined fields routines
# $Id$
# Notes:
#	- User-defined fields exist in the database
#	with the `ud_' prefix to provide namespace
#	avoidance with our own fields and/or database
#	keywords.

use DBH qw(:all);
use Storable;
use strict;

use constant FLD_USER => 1;

sub _udf_init {
	my $this = shift;
	$this->udf_update() unless exists $this->{skip_init} && $this->{skip_init};
}

sub udf_validate {
	my ($this, $type, $data) = @_;
	my @errs = ();
	my %flds = ();
	my %map = (
		FLD_USER() => "user_fields",
	);

	$this->throw("Unrecognized field type; type: $type") unless exists $map{$type};

	# We will process all items and generate as much error
	# information as possible in hopes that the user will
	# not multiply submit data, correcting errors only one
	# at a time.
	#
	# This setup requires that if a field is required and
	# does not provide a validation pattern (implying a
	# non-empty field), the `validation' value must take
	# on qr//;
	my ($field_id, $field);
	while (($field_id, $field) = each %{ $this->{$map{$type}} }) {
		if ($field->{validation}) {
			unless (exists $data->{$field_id} && $data->{$field_id} &&
				$data->{$field_id} =~ $field->{validation}) {
				if ($field->{required}) {
					push @errs, $field_id;
				} else {
					$data->{$field_id} = $field->{default_value};
				}
			}
		}

		# No need in preparing data if an
		# error occurred.
		unless (@errs) {
			$data->{$field_id} = $this->str_parse(
				$data->{$field_id}, $field->{parse});
		}
	}

	return \@errs;
}

# Checks to see if the user-defined fields fingerprints
# have changed and updates the structures accordingly.
sub udf_update {
	my $this = shift;
	my $change = FALSE();
	my %old_types;
	my %changed = ();
	my $mod_date;

	# Grab last user-defined fields "signature"/fingerprint
	(@old_types{qw(user_fields)}, $mod_date) =
		$this->{dbh}->query("	SELECT
						user_fields_sig,
						mod_date
					FROM
						thraxx_config", DB_ROW);
	my ($field_id, $field_sig, $old_fields);
	while (($field_id, $field_sig) = each %old_types) {
		eval {
			$old_fields = Storable::thaw($field_sig);
		};
		if ($@) {
			$old_fields = {};
			# Reset for future use
			$@ = "";
		}
		$old_fields = {} unless ref $old_fields eq "HASH";
		if ($this->hasheq($old_fields, $this->{$field_id})) {
			$change = TRUE();
			$changed{$field_id} = $old_fields;
		}
	}

	if ($change) {
		my $file = $this->{config};
		my $rmtime = Timestamp->new($mod_date)->get_unix;
		my $lmtime = (stat $file)[9];
		# These should never be equal
		if ($rmtime <= $lmtime) {
			# Remote timestamp is older than local
			# timestamp: configuration information
			# must have been updated locally.
			$this->udf_update_db(\%changed);
		} else {
			# Local timestamp is older than remote
			# timestamp: remote configuration must
			# have changed. Make sure this doesn't
			# happen again.
			$this->write_config($rmtime);
			if (utime($rmtime, $rmtime, $file) != 1) {
				$this->throw("Cannot call utime(); file: $file");
			}
		}
	}
}

# An update has occured, write the new structure out to the database.
sub udf_update_db {
	my ($this, $changed) = @_;
	my $dbh = $this->{dbh};

	# Mapping between field types and database table names
	my %map = (
		user_fields => "thraxx_users",
	);

	my ($id, @removed, %diff, $field_id, $field,
	    $new_field_id, $new_field, $old_fields, %sigs);

	while (($id, $old_fields) = each %$changed) {
		# Removed fields
		@removed = ();

		# "Difference" fields (i.e., new fields)
		%diff = %{ $this->{$id} };

		while (($field_id, $field) = each %$old_fields) {
			if (exists $diff{$field_id} &&
			    $this->hasheq($diff{$field_id}, $field)) {
				# Field exists in both; remove
				delete $diff{$field_id};
			} else {
				# There's a difference (new field); save for later
				push @removed, $field_id;
			}
		}

		# Removed dropped fields
		foreach (@removed) {
			$dbh->query("	ALTER TABLE
						$map{$id}
					DROP
						ud_$_", DB_NULL);
		}

		# Add new fields
		while (($new_field_id, $new_field) = each %diff) {
			$dbh->query("	ALTER TABLE
						$map{$id}
					ADD
						ud_$new_field_id $new_field->{database_type}", DB_NULL);
		}

		# Create signature on current/"next" fields
		$sigs{$id} = $dbh->prepare_str(Storable::freeze($this->{$id}), SQL_REG);
	}

	# Update signatures
	if ($dbh->query("	SELECT
					COUNT(*)
				FROM
					thraxx_config", DB_COL)) {
		# Already exists; update
		$dbh->query("	UPDATE
					thraxx_config
				SET
					user_fields_sig = '$sigs{user_fields}',
					mod_date = NOW()", DB_NULL);
	} else {
		# Doesn't exist; insert
		$dbh->query("	INSERT INTO
					thraxx_config
				(
					user_fields_sig,
					mod_date
				) VALUES (
					'$sigs{user_fields}',
					NOW()
				)", DB_NULL);
	}
}

return TRUE();
