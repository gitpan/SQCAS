package SQCAS::Apache::Authentication;


=head1 NAME

SQCAS::Apache::Authentication - Apache handler for authenticating users.

=head1 SYNOPSIS

  use SQCAS::Apache::Authentication;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::Apache::Authentication.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for SQCAS::Apache::Authentication, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.

=cut

use 5.008;
use strict;
use CGI qw(Vars);
# in real use should use Apache::Constants not rvals
use SQCAS qw(:all);
use SQCAS::Apache;
use Apache::Constants qw(:common);


our $VERSION = '0.4';

=head1 METHODS


=head2 handler

This function is called to verify the username and password provided to the
login CGI by the user. It will imediatly return unless both the username and
password were provided (well, technically, evaluate to true). It then connects
to the database (using DNAcore::Auth) and gets the user ID and password for the
supplied username.

Perls crypt function is called using the suplied password as the word and the
password from the db as the salt. If the result matches the stored password,
access will be granted. A session key is generated using md5_hex and the user
ID, remote IP and time are stored in the db on that key.

If authentication fails, the reason is returned. Otherwise the OK Apache
constant is returned.

## NEW

OK, since this will be the same - server version we can continue to use
custom_response. It's worth noting however that the remote check version
needs to return just the AUTH_REQUIRED response & let the caller handle
redirects.

%CONFIG comes from base class

 ###
 # COOKIE is the biggest hangup I have ATM in making this function as a truly
 # centralized authorization server. It looks like I can specify the domain
 # name as well as path in HTTP1.1, but I have yet to test this, nor do I
 # know the syntax using set_header. But in theory I can loop over all defined
 # domains (yeah, I need to extend schema to record them) that SQCAS services
 # and set the cookie in that domain.
 ###


##

=cut
sub handler {
    my $apache = shift; # apaches request object
    return OK unless $apache->is_initial_req;
    my $user = shift || '';
    my $sent_pw = shift || '';
	my $start_url = $CONFIG{WELCOME_PAGE};
	
	# if the session token is available, they are logged in, let authz work
	my $cookie_name = $apache->dir_config('COOKIE_NAME') || $CONFIG{COOKIE_NAME};
	my $cookies = $apache->header_in('Cookie') || '';
    return OK if $cookies =~ /$cookie_name=/
		|| $apache->err_header_out($cookie_name);

	my $CGI = new CGI;
	
	gripe("user = $user, sent_pw = $sent_pw, start_url = $start_url\n")
		if $CONFIG{DEBUG};
	unless ($user && $sent_pw) {
		my %params = $CGI->Vars;
		$user = $params{Username} || '';
		$sent_pw = $params{Password} || '';
		$start_url = $params{uri} if exists $params{uri};
	} # if no user info passed in, check for form submisison
	gripe("CGI'd: user = $user, sent_pw = $sent_pw, start_url = $start_url\n")
		if $CONFIG{DEBUG};
    #my $log = $apache->log;
	
    
	my $debug =  $apache->dir_config('DEBUG') || $CONFIG{DEBUG};
	my $loginURI = $apache->dir_config('LOGIN_URI') || $CONFIG{LOGIN_URI};
    my $rem_ip = $apache->connection->remote_ip;
	
	# any failures should return user to the login page
	$apache->custom_response(AUTH_REQUIRED, "$loginURI?code=" . AUTH_REQUIRED);
	$apache->custom_response(FORBIDDEN, "$loginURI?code=" . FORBIDDEN);
	
    # need both pieces to proceed
	gripe('Username is required') && return AUTH_REQUIRED
		unless $user;
	gripe('Password is required') && return AUTH_REQUIRED
		unless $sent_pw;
	
	# OK, validate user
	my ($valid_user,$Skey) = check_authentication({USER => $user,
		PASSWORD => $sent_pw, IP => $rem_ip, DEBUG => $debug});
	
	# if invalid, log reason and return user to login page
	gripe($CONFIG{ERRSTR}) && return AUTH_REQUIRED
		if $valid_user == AUTH_REQUIRED;
    
	# just to be paranoid
	error("Invalid token returned -$Skey-!?")
		unless $Skey && length($Skey) == 32;
	
	###
	# This will need to loop over all domains defined as clients in the
	# SQCAS database and set a cookie of the appropriate name for each
	# client domain
	
    # need to set the path to root, otherwise it defaults to request directory
	$apache->header_out("Set-Cookie" => "$cookie_name=$Skey; PATH=/");
	
	# check for cookie and compare users before auto forwarding to params{uri}
    gripe("Redirecting to $start_url.") if $CONFIG{DEBUG};
	print $CGI->redirect("$start_url");

	return OK; # does this get seen at all or does the redirect handle it?
} # handler


1;
__END__

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Apache::Authentication

=item 0.4

First prototype, adapted from concepts in the functional MGH::Auth module.

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

Copyright 2004 by Sean Quinlan, Trustees of Boston University

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
