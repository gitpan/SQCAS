package SQCAS::Apache::Login;

=head1 NAME

SQCAS::Apache::Login -Apache handler for loging in users.

=head1 SYNOPSIS

  use SQCAS::Apache::Login;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::Apache::Login.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for SQCAS::Apache::Login, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.

=cut

use 5.008;
use strict;
use CGI qw(:standard);
use SQCAS::Apache;
use SQCAS qw(:all);
use Apache::Constants qw(:common);

our $VERSION = '0.2';

=head1 METHODS

=head2 B<handler()>

This handler generates the login form. I'd love it to be a little pop-up.

The form action should point to a uri for which SQCAS::Apache::Authenticate is
the handler. That handler should redirect to the requested page (or default
welcome page otherwise), or return user here.

=cut
sub handler {
	my $apache = shift;
	my $CGI = new CGI;
	my %params = $CGI->Vars;
	
	my $message = '';
	$message = "code = $params{code}" if $CONFIG{DEBUG};
	if (exists $params{code} && $params{code} == AUTH_REQUIRED) {
		$message = "User authentication required:";
	} # if auth required
	
	elsif (exists $params{code} && $params{code} == FORBIDDEN) {
		$message = "User authentication failed:";
	} # if forbidden - I don't think this should be a return case
		
	my $warnings = warning_notes();
	
	print $CGI->header, $CGI->start_html("SQCAS default login page");
	print "$message\n$warnings\n\n";
	print $CGI->h1("Please enter username and password:"), "\n";
	print $CGI->start_form(-action => $CONFIG{AUTHENTICATION_URI}), "\n",
		"Username: ";
	print $CGI->textfield(-name => 'Username',
		-default => $params{Username}), "\n";
	print $CGI->p, "Password: ";
	print $CGI->password_field('Password'), "\n";
	print $CGI->hidden('uri', $params{uri}), "\n";
	print $CGI->p, $CGI->submit, "\n", $CGI->end_form, "\n";
	print $CGI->end_html;
} # handler


1;

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -ACX
	-n
	SQCAS::Apache::Login

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

Copyright 2004 by Sean Quinlan, Boston University Trusties

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
