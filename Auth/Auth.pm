package SQCAS::Auth;

=head1 NAME

SQCAS::Auth - Perl extension for blah blah blah

=head1 SYNOPSIS

  use SQCAS::Auth;
  blah blah blah

=head1 DESCRIPTION

An Apache auth handler.

=head2 EXPORT

None by default.

=cut

use 5.00800;
use strict;
use warnings;

# in real use should use Apache::Constants not rvals
use SQCAS qw(:all);
#use Apache::Constants qw(:common);


our $VERSION = '0.1';


=head1 METHODS


=head2 handler

Apaches access point. Although this module is invoked during authentication,
it doesn't actually handle authentication at that time. Because it's configured
this way it could, or it could do other housekeeping tasks. At the moment all
this method does is set this modules authorize function as the handler for the
Authorization phase. I did it this way bacuase it's how it was recommended in
the eagle - I suspect to prevent possible odd behavior by trying to do Authz
without Authen??

This function takes no input arguments. Should be replaced with local version.

=cut
sub handler {
    my $r = shift; # apaches request object
    $r->push_handlers(PerlAuthzHandler => \&MGH::Auth::authorize);
    return OK;
} # handler


=head2 authorization

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
sub authorize {
    my $r = shift; # apaches request object
    # no sense doing this for every subrequest, such as getting the footer or
    # generating an image
    return OK unless $r->is_initial_req;
	
	my $cookie_name = $r->dir_config('COOKIE_NAME') || $CONFIG{COOKIE_NAME};
	my $debug =  $r->dir_config('DEBUG') || $CONFIG{DEBUG};
	my $loginURI = $r->dir_config('LOGIN_URI') || $CONFIG{LOGIN_URI};
	my $forbiddenURI = $r->dir_config('FORBIDDEN_URI')
		|| $CONFIG{FORBIDDEN_URI};
    my $rem_ip = $r->connection->remote_ip;
	
	my $request = $r->uri;
	$r->custom_response(AUTH_REQUIRED, "$loginURI?uri=$request");
	$r->custom_response(FORBIDDEN, "$forbiddenURI?uri=$request");
	
	my $client = $r->dir_config('CLIENT') || 0;
	unless ($client) {
		my $uri = $r->parsed_uri;
		my $domain = $uri->hostname;
		$client = $CONFIG{CLIENTS}{$domain};
		unless ($client) {
			$r->log_reason('Client ID required, none provided and domain '
				. "$domain not found in DB", $r->filename);
			return FORBIDDEN;
		} # no client provided and couldn't find by domain
	} # client required
	
	my $timeout = $r->dir_config('TIMEOUT')
		|| $CONFIG{CLIENTS}{$client}{Timeout};
	
    my $cookies = $r->header_in('Cookie') || '';
    $cookies    =~ /$cookie_name=(\w*)/;
    my $cookie  = $1 || '';
	my $is_authorized = check_authorization({COOKIE => $cookie,
		URI => $request, DEBUG => $debug, IP => $rem_ip,
		TIMEOUT => $timeout});
	
	error("Could not authorize: $CONFIG{ERRSTR}") if $is_authorized == ERROR;
	return OK if $is_authorized == OK;
	
	if ($is_authorized == AUTH_REQUIRED) {
        $r->log_reason("Authorization will require authentication first: "
			. "$CONFIG{ERRSTR}.", $r->filename);
        return AUTH_REQUIRED; # should redirect to please log in page
	} # redirect to login server so user can get authenticated
	
	if ($is_authorized == FORBIDDEN) {
		$r->log_reason("User not authorized to access $request: "
			. "$CONFIG{ERRSTR}"); 
		return FORBIDDEN;
	} # user was denied, redirect to appropriate page
	
	error("Didn't know how to handle authorize result: $is_authorized");
} # authorize handler


=head2 authenticate

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
sub authenticate {
    my $r = shift; # apaches request object
    my $user = shift;
    my $sent_pw = shift;
    my $log = $r->log;
	
    
	my $debug =  $r->dir_config('DEBUG') || $CONFIG{DEBUG};
	my $loginURI = $r->dir_config('LOGIN_URI') || $CONFIG{LOGIN_URI};
    my $rem_ip = $r->connection->remote_ip;
	
	# any failures should return user to the login page
	$r->custom_response(AUTH_REQUIRED, "$loginURI");
	$r->custom_response(FORBIDDEN, "$loginURI");
	
    # need both pieces to proceed
	$r->log_reason('Username is required') && return AUTH_REQUIRED
		unless $user;
	$r->log_reason('Password is required') && return AUTH_REQUIRED
		unless $sent_pw;
	
	# OK, validate user
	my ($valid_user,$Skey) = check_authentication({USER => $user,
		PASSWORD => $sent_pw, IP => $rem_ip, DEBUG => $debug});
	
	# if invalid, log reason and return user to login page
	$r->log_reason($CONFIG{ERRSTR}) && return AUTH_REQUIRED
		if $valid_user == AUTH_REQUIRED;
    
	# just to be paranoid
	error("Invalid token returned -$Skey-!?")
		unless $Skey && length($Skey) == 32;
	
	###
	# This will need to loop over all domains defined as clients in the
	# SQCAS database and set a cookie of the appropriate name for each
	# client domain
	
    # need to set the path to root, otherwise it defaults to request directory
	my $cookie_name = $r->dir_config('COOKIE_NAME') || $CONFIG{COOKIE_NAME};
    $r->header_out("Set-Cookie" => "$cookie_name=$Skey; PATH=/");
	
    return OK;
} # authenticate


1;

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -XAC
	-n
	SQCAS::Auth

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

SeanQuinlan, E<lt>seanq@suse.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by SeanQuinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
