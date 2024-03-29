package SQCAS::Admin;

use 5.008;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use SQCAS::Admin ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';


# Preloaded methods go here.

1;
__END__

=head1 NAME

SQCAS::Admin - Stub module to make Makefile.PL build subdirectories properly.
Need to find a better way.

=head1 SYNOPSIS

  use SQCAS::Admin;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::Admin.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

This is a placeholder.

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Admin

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@darwin.bu.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
