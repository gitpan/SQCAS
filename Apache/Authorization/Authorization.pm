package SQCAS::Apache::Authorization;


=head1 NAME

SQCAS::Apache::Authorization - Apache handler for authorizing users.

=head1 SYNOPSIS

  use SQCAS::Apache::Authorization;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::Apache::Authorization.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for SQCAS::Apache::Authorization, created by h2xs. It looks
like the
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
use Apache::URI;
use Apache::Constants qw(:common);

our $VERSION = '0.5';


=head1 METHODS


=head2 handler

This is the function that actually controls the per request access. It first
tries to get the value of the cookie for the access region. If no cookie is
found it returns AUTH_REQUIRED. If it does find a value associated with the
cookie, it then checks to see if the session has timed out. If it has, it
returns AUTH_REQUIRED. If not, it updates the request timestamp (resetting the
timer) and returns OK. Current timeout period is 15 minutes.

If an AUTH_REQUIRED value is returned, custom_response is also set to point the
browser to the login page. The reason authorization was not granted and the
originally requested URI are also passed to the login page.

This function takes no input arguments.

## NEW

OK, since this will be the same - server version we can continue to use
custom_response. It's worth noting however that the remote check version
needs to return just the AUTH_REQUIRED response & let the caller handle
redirects.

%CONFIG comes from base class

IP:	The IP the user connected from. If an IP is found in the Session table
(which it will if it was provided during authentication) than this argument is
required and must match.

##

=cut
sub handler {
    my $r = shift; # apaches request object
    $r->push_handlers(PerlAuthzHandler =>
		\&SQCAS::Apache::Authorization::authorize);
    return OK;
} # handler
# doing this in this bazaar way seems to be the only simple way for me to get
# the authz code called on all appropriate requests and handle authen correct

sub authorize {
    my $apache = shift; # apaches request object
    # no sense doing this for every subrequest, such as getting the footer or
    # generating an image
	return OK unless $apache->is_initial_req;
	
	my $cookie_name = $apache->dir_config('COOKIE_NAME') || $CONFIG{COOKIE_NAME};
	my $debug =  $apache->dir_config('DEBUG') || $CONFIG{DEBUG};
	# having a weird problem with %CONFIG getting here - but not modified!?!
	my $loginURI = $apache->dir_config('LOGIN_URI')
		|| $CONFIG{LOGIN_URI};
	my $forbiddenURI = $apache->dir_config('FORBIDDEN_URI')
		|| $CONFIG{FORBIDDEN_URI};
	my $rem_ip = $apache->connection->remote_ip;
	gripe("URI_BASE = $CONFIG{URI_BASE}, loginURI = $loginURI, forbiddenURI = $forbiddenURI") if $debug;
	
	my $request = $apache->uri;
	# allow acess to public directory where Login, NewUser and such are stored
	gripe("Auth request received for $request from $rem_ip.") if $debug;
	return OK if $request =~ m{$CONFIG{URI_BASE}/public/};
	
	$apache->custom_response(AUTH_REQUIRED,
		"$loginURI?uri=$request&code=" . AUTH_REQUIRED);
	$apache->custom_response(FORBIDDEN, "$forbiddenURI?uri=$request");
	
	my $client = $apache->dir_config('CLIENT') || 0;
	unless ($client) {
		my $uri = $apache->parsed_uri;
		my $domain = $uri->hostname;
		$client = $CONFIG{CLIENTS}{$domain};
		unless ($client) {
			gripe('Client ID required, none provided and domain '
				. "$domain not found in DB.");
			return FORBIDDEN;
		} # no client provided and couldn't find by domain
	} # client required
	
	my $timeout = $CONFIG{CLIENTS}{$client}{Timeout}
		|| $apache->dir_config('TIMEOUT') || $CONFIG{TIMEOUT};
	
	my $cookies = $apache->header_in('Cookie') || '';
	$cookies    =~ /$cookie_name=(\w*)/;
	my $cookie  = $1 || '';
	
	unless ($cookie) {
		# check err_header in case auth internal redirect
		$cookie = $apache->err_header_out($cookie_name);
		if ($cookie) {
			$apache->header_out("Set-Cookie" => "$cookie_name=$cookie; PATH=/");
		} # set cookie in response
		
		else {
			my $CGI = new CGI;
			my %params = $CGI->Vars;
			$cookie = $params{$cookie_name};
		} # not internal redirect, CGI param?
		gripe("cookie_name $cookie_name found $cookie.") if $CONFIG{DEBUG};
		
		(gripe("No cookie named $cookie_name found.")
			&& return AUTH_REQUIRED) unless $cookie;
	} # if no cookie
	
	gripe("COOKIE => $cookie, URI => $request, TIMEOUT => $timeout, CLIENT => $client");
	my $is_authorized = check_authorization({COOKIE => $cookie,
		URI => $request, DEBUG => $debug, IP => $rem_ip,
		TIMEOUT => $timeout, CLIENT => $client, RESOURCE => $request,
		MASK => 'read'});
	
	error("Could not authorize: $CONFIG{ERRSTR}") if $is_authorized == ERROR;
	return OK if $is_authorized == OK;
	if ($is_authorized == AUTH_REQUIRED) {
        gripe("Authorization will require authentication first: "
			. "$CONFIG{ERRSTR}.");
        return AUTH_REQUIRED; # should redirect to please log in page
	} # redirect to login server so user can get authenticated
	
	if ($is_authorized == FORBIDDEN) {
		gripe("User not authorized to access $request: "
			. "$CONFIG{ERRSTR}."); 
		gripe("Should be redirected to $forbiddenURI.");
		return FORBIDDEN;
	} # user was denied, redirect to appropriate page
	
	error("Didn't know how to handle authorize result: $is_authorized");
} # authorize handler

1;
__END__
=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Apache::Authorization

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
