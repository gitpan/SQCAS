package SQCAS;

=head1 NAME

SQCAS - Centralized Authorization Server

=head1 SYNOPSIS

  use SQCAS;

OK, as of V.12 this code now passes a basic set of tests. This means that
the basic methods for checking authentication and authorization in this module
are working. That requires that the SQCAS::_config module is doing it's job and
that the current core methods in the SQCAS::DB module function. The SQCAS::Auth
module for working under mod_perl should be basically correct since it is based
on an existing mod_perl module I've used elsewhere but calls the methods in
SQCAS.pm. However it has not been tested yet and likely contains some syntax
errors at the minimum.

The documentation below was writen before I got all the basics working, so while
the basic premises hold, there may be some changes from original plan to first
working implementation which are not reflected. I'll
update the docs next to match this basic working version.

=head1 DESCRIPTION

This package is intended as the central authorization code. Packages in this
namespace would be provided that subclass (C<base qw(SQCAS)>) this package and
provide appropriate extended interfaces, such as mod_perl handlers.
The first version of this code will simply be a slightly reworked cut-and-paste
of my original work for the MGH DNA core Auth modules. I intend to move rapidly
from that stage to a more portable, base class.

This is an abstract base class - it DOES NOT FUNCTION on it's own. It will expects
that $self is the Apache request object and that it contains certain properties,
which must have been set up by the child class where the handler method was
defined.

Initially I just want this to work on the same server using Perl CGI's &
handlers. In fact, I want to provide a fairly generic auth handler and login
handler (and maybe a cgi login). Although a later project might be to design
the included code such that it templates well, the intent is that users would
modify them to look & feel appropriate for their own sites (or just tear out the
guts and use elsewhere).

The next phase would be to provide special request handlers for authentication
and authorization. The response code in the header will indicate if
the user is authorized or not, or if they are allowed to view a given resource
or not. On authentication the handler would return XML or YAML containing
whatever data the server had on a user, most importantly the ID. Another handler
could perhaps handle later data requests for systems that don't store the data
retrieved on authentication automatically.

So, on the back end the CAS server would require a small set of tables. Since
this system is intended as a single point of maintenance of user data we can
control the schema. It would be nice if this could work with an LDAP server as
well as a MySQL (or other DBI supported relational database). I suppose the
system should also provide pages for users to update their information as well
as a mechanism for adding new users, both via a default page and submission via
an authorized administrative user.

Some paranoia levels or checks could also be defined, for instance requiring
that all authorization requests include the requesters IP and making sure it
matches the one sent with authentication request.

=head2 RESPONSE CODES

	000	ERROR
	200	OK
	401	AUTH_REQUIRED
	403	FORBIDDEN


=head2 EXPORT

&check_authorization

&check_authentication

%CONFIG

B<TAG:> exceptions

error

gripe

B<TAG:> rvals

ERROR

OK

AUTH_REQUIRED

FORBIDDEN

=cut

use 5.008000;
use strict;
use SQCAS::_config;
use Digest::MD5 qw(md5_hex);


use constant ERROR => 000;
use constant OK => 200;
use constant AUTH_REQUIRED => 401;
use constant FORBIDDEN => 403;

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( exceptions => [ qw(error gripe) ],
	rvals => [ qw(ERROR OK AUTH_REQUIRED FORBIDDEN) ],
	all => [ qw(error gripe ERROR OK AUTH_REQUIRED FORBIDDEN
		%CONFIG check_authorization check_authentication) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

#our @EXPORT = qw(%CONFIG check_authorization check_authentication);


our $VERSION = '0.2';


=head1 METHODS

=head2 check_authorization

This checks the database to see if the user is currently logged in and if they
are allowed to use the specified resource.

It expects to be called in an object oriend fashion, getting $self as the first
argument. If not called this way, just feed it an anonymous reference. It's
not how I want to handle it perminantly, just for getting the first draft
working.

PARAMETERS:


 ###
 # COOKIE is the biggest hangup I have ATM in making this function as a truly
 # centralized authorization server. It looks like I can specify the domain
 # name as well as path in HTTP1.1, but I have yet to test this, nor do I
 # know the syntax using set_header. But in theory I can loop over all defined
 # domains (yeah, I need to extend schema to record them) that SQCAS services
 # and set the cookie in that domain.
 ###

COOKIE:	The session token returned by SQCAS when the user was authenticated
and logged in. This is used to get the user information required for checking
that user is logged in and that their session has not timed out. ***SECURITY***
It is up to you to make sure that this value is kept private and secure during
the session.

RESOURCE:	This is the resource definition that will be checked in the
database.

CLIENT:	The client ID or domain from which this request is being made.

OPTIONS:

MASK:	This is the permissions mask that will be checked for the specified
RESOURCE. If not defined a read permission request is assumed by default.
*** Should this be made a required argument instead?

IP: The remote IP of the user. If this was provided during authentication than
it is REQUIRED for authorization and the IP's must match.

TIMEOUT:	The timeout for sessions in seconds.

=cut
# change $r to $self
sub check_authorization {
	# if we were based and called in OO style, shift the object ref away
	# we don't use it here
	my $self = shift if (ref($_[0]) && ref($_[0]) !~ /HASH/
		&& $_[0]->can('check_authorization'));
	
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $debug = $params{DEBUG} || $CONFIG{DEBUG} || 0;
	
	unless ($params{CLIENT}) {
		$CONFIG{ERRSTR} = "No client info provided.";
		return ERROR;
	} # client required
	
	my $client = 0;
	if ($params{CLIENT} =~ /^\d+$/) { $client = $params{CLIENT} }
	else {
		my $Qdomain = $CONFIG{DBH}->quote($params{CLIENT});
		$client = $CONFIG{DBH}->selectrow_array("SELECT ID FROM Clients
			WHERE Domain = $Qdomain");
		error("Problem fetching client ID with $Qdomain: "
			. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
		
		unless ($client) {
			$CONFIG{ERRSTR} = "No client info provided.";
			return ERROR;
		} # client required
	} # else look for domain in DB
	
	unless ($params{RESOURCE}) {
		$CONFIG{ERRSTR} = "No resource to authorize against provided.";
		return ERROR;
	} # resource to check authorization against required
	
    unless ($params{COOKIE}) {
        $CONFIG{ERRSTR} = "No cookie($params{COOKIE}) available for "
			. "authorization on request $params{RESOURCE}";
        return ERROR;
    } # session token required
	
	my $Qcookie  = $CONFIG{DBH}->quote($params{COOKIE});
	
	my $logged_ip = $CONFIG{DBH}->selectrow_array("SELECT IP
		FROM Session WHERE ID = $Qcookie");
	error('Problem cheking for logged IP: ' . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	# if an IP was logged when authenticated, the provided IP must match
	if ($logged_ip && $logged_ip ne $params{IP}) {
        $CONFIG{ERRSTR} = "Current IP does not match IP when you logged "
			. "on. This may indicate a 'man in the middle' security attack.";
        return AUTH_REQUIRED;
	} # if IP & ip doesn't match
	
	my $timeout = $params{TIMEOUT} || $CONFIG{TIMEOUT} || 900;
	
	my $get_timediff = $CONFIG{DBH}->prepare("SELECT unix_timestamp()
		- unix_timestamp(TS) FROM Session WHERE ID = $Qcookie",
		{RaiseError => 1});
	error("Problem preparing timediff statement: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	$get_timediff->execute();
	error("Problem executing timediff statement: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	my $timediff = $get_timediff->fetchrow_array();
	error("Problem fetching timediff: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	my $try = 2;
	unless (defined $timediff) {
		$CONFIG{ERRSTR} = "Session ID $Qcookie not in database.";
		return AUTH_REQUIRED;
	} # session token not found in db
	
	elsif ($timediff == 0) {
		while ($timediff == 0) {
			#$log->warn("DB connection difficulties trying again ($try)\n");
			sleep(1);
			$get_timediff->execute();
			error("Problem executing timediff statement: "
				. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
			
			$timediff = $get_timediff->fetchrow_array();
 			error("Problem fetching timediff: " . $CONFIG{DBH}->error)
				if $CONFIG{DBH}->error;
			
			last if $try++ == 8;
		} # while timediff not true
		
		unless ($timediff) {
			$CONFIG{ERRSTR} = "Session ID $Qcookie not in database.";
			return AUTH_REQUIRED;
		} # unless second query suceeded
	} # session token not found
	
	elsif ($timediff > $timeout) {
        $CONFIG{ERRSTR} = "Session has timed out.";
        return AUTH_REQUIRED;
	} # if session cookie valid
		
	$CONFIG{DBH}->userdat($params{COOKIE}); # leave it cached in DBH
	
	my $HR_allowed_params = {RESOURCE => $params{RESOURCE}, CLIENT => $client};
	$HR_allowed_params->{MATCHKEY} = $params{MATCHKEY}
		if exists $params{MATCHKEY};
	$HR_allowed_params->{MASK} = $params{MASK} if exists $params{MASK};
	unless ($CONFIG{DBH}->allowed($HR_allowed_params)) {
       	$CONFIG{ERRSTR} = "User for session $Qcookie not authorized to access "
			. "$params{RESOURCE}"; 
		return FORBIDDEN;
	} # unless user has permision
		
	$CONFIG{DBH}->do("UPDATE Session SET TS=NULL WHERE ID = $Qcookie");
	error("Problem updating timestamp for $Qcookie: " .
		$CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	return OK;
} # check_authorization



=head2 check_authentication

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

PARAMETERS:

USER:	The username.

PASSWORD:	The users password.

OPTIONS:

IP: The remote connection IP. If present at authentication will be required
to be provided and match during any subsiquent authorization check.

=cut
sub check_authentication {
	# if we were based and called in OO style, shift the object ref away
	# we don't use it here
	my $self = shift if (ref($_[0]) && ref($_[0]) !~ /HASH/
		&& $_[0]->can('check_authorization'));
	
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $debug = $params{DEBUG} || $CONFIG{DEBUG} || 0;
		
	unless ($params{USER}) {
		$CONFIG{ERRSTR} = "No username provided.";
		return ERROR;
	} # resource to check authorization against required
	
	unless ($params{PASSWORD}) {
		$CONFIG{ERRSTR} = "No password provided.";
		return ERROR;
	} # resource to check authorization against required
	
    # OK, now we have a username, lets check the suplied password
    my $reason = '';
    
    my $Quser = $CONFIG{DBH}->quote($params{USER});
    # now get userID and password for username
    my ($userID,$passwd) = $CONFIG{DBH}->selectrow_array("SELECT User, Password 
		FROM Users WHERE Username = $Quser");
    error("Database error: " . $CONFIG{DBH}->error) if $CONFIG{DBH}->error;    
	
	unless ($userID) {
    	 $CONFIG{ERRSTR} = "Invalid account, username $params{USER} not found";
		 return AUTH_REQUIRED;
	} # unless user id returned
	unless ($passwd eq crypt($params{PASSWORD},$passwd)) {
    	$CONFIG{ERRSTR} = "Incorrect password";
		return AUTH_REQUIRED;
    } # unless password suplied matches users in db
	
    # OK, user authenticated, now provide a session token
    my $now = localtime;
    my $Skey = md5_hex("$0$passwd$params{USER}$now");
	my $Qkey = $CONFIG{DBH}->quote($Skey);
	
    $CONFIG{DBH}->do("INSERT INTO Session (ID, User, IP)
		VALUES ($Qkey,$userID,'$params{IP}')");
    error("Can't log user in: " . $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	# make sure DB has a chance to unlock before returning
    sleep(1);
	
    return (OK,$Skey);
} # check_authentication



sub error {
	die shift;
} # error

sub gripe {
	warn shift;
} # gripe

1;

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -XAC -n SQCAS

=item 0.1

Initial code port.

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
