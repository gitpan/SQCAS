package SQCAS::_config;

use 5.008;
use strict;
use YAML;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(%CONFIG);

our $VERSION = '0.1';

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

# connect to db
use SQCAS::DB;
eval { $CONFIG{DBH} = SQCAS::DB->connectDB({user => $CONFIG{DB_USER},
	password => $CONFIG{DB_PASSWD}, host => $CONFIG{DB_HOST}}) };
	
die "Problem connecting to database: $@" if $@;

$CONFIG{CLIENTS} = $CONFIG{DBH}->client_info;

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

SQCAS::_config - Perl extension for blah blah blah

=head1 SYNOPSIS

  use SQCAS::_config;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::_config.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for SQCAS::_config, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::_config

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
