package SQCAS::_config;

use 5.008;
use strict;
use YAML;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(%CONFIG);

our $VERSION = '0.4';

# read in config file and set up global %CONFIG - this should
# be usable as is by any module that bases this package? And if
# this module is included at server start up, parsing of the config file should
# happen only once. Would be best if this was write only, but this will do
# for now
local $/ = undef; # slurpy

open(YAML,'/etc/SQCAS.yaml') or die "Couldn't open SQCAS config files: $!";
my $yaml_in = <YAML>;
close YAML or gripe("YAML didn't close preoperly: $!");

my $HR_config_params = Load($yaml_in);
our %CONFIG = %{$HR_config_params};

$^W++ if $CONFIG{DEBUG};
require diagnostics && import diagnostics
	if $CONFIG{DEBUG} && $CONFIG{DEBUG} > 2;

#warn "URI_BASE=$CONFIG{URI_BASE}";
foreach my $uri (grep(m/_URI$/, keys %CONFIG)) {
#	die "remapping: $CONFIG{$uri} -> $CONFIG{URI_BASE}$CONFIG{$uri}\n";
	$CONFIG{$uri} = "$CONFIG{URI_BASE}$CONFIG{$uri}";
} # for each uri
warn "LOGIN_URI=$CONFIG{LOGIN_URI}\n";

# connect to db
use SQCAS::DB;
eval { $CONFIG{DBH} = SQCAS::DB->connectDB({user => $CONFIG{DB_USER},
	password => $CONFIG{DB_PASSWD}, host => $CONFIG{DB_HOST}}) };
	
die "Problem connecting to database: $@" if $@;

$CONFIG{CLIENTS} = $CONFIG{DBH}->client_info;

# get user info table fields - will it get used a lot? Should we get the
# client tables as well then? Should the field type be a value?
foreach my $field (grep($_ ne "ID",
		@{$CONFIG{DBH}->selectcol_arrayref("DESC UserInfo")})) {
	$CONFIG{USER_INFO_FIELDS}{$field} = 1;
} # foreach field in the UserInfo table

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

SQCAS::_config - Reads SQCAS.yaml config file, connects to database and sets
up systems %CONFIG hash.

=head1 SYNOPSIS

  Not to be used directly. Called by SQCAS.

=head1 ABSTRACT

  Reads SQCAS.yaml config file, connects to database and sets
  up systems %CONFIG hash.

=head1 DESCRIPTION

Not for direct use.

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::_config

=item 0.1

Reads YAML config file from /etc/, connects to database, sets up client lists
and user table hash.

=back



=head1 SEE ALSO

L<SQCAS>

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@darwin.bu.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
