package SQCAS;

=head1 NAME

SQCAS - Centralized Authorization Server

=head1 SYNOPSIS

  use SQCAS;


=head1 DESCRIPTION

This system provides a set of tools providing access to a centralized
authorization database. While the system is intended to be accessed through
web pages served on a mod_perl/Apache server, the basic functionality does not
require Apache and could be used as a library of access objects for seperate
development.

This module is intended to be usable either functionally or as an abstract
base class. It provides the core check_authentication and check_authorization
methods as well as the result codes as constants.

As of version .2 all the basic functionality is in place. The automated tests
for SQCAS pass, and I've installed the Apache Auth* and Login modules and set
up a simple website with protected resources and tested that the minimal
functional behavior is in place. See SQCAS/README and SQCAS/Apache/README for
details on setting up the database and webserver.

The system requires a client ID to determine the auth* realm for requests, but
will try to guess it (when accessed via Apache) by looking up the requests
domain if it wasn't provided. If the users IP is provided during authentication,
which the Apache tools do automatically, then all authorization requests will
require an IP match.

* Where I use Auth* I'm refering to both authorization and authentication.

head2 INTENT

Initially I just want this to work on the same server using mod_perl
handlers. Fairly generic auth handlers and a login
handler are provided. Although a later project might be to design
the included code such that it templates well, the intent is that users would
modify them to look & feel appropriate for their own sites (or just tear out the
guts and use elsewhere). By version 0.4 the system will include handlers and
base modules for new user registration & account maintenance, for admins to
grant permissions to users and groups, and for managing groups. Hopefully
I'll have completed the documentation by then too! :)

The next phase would be to provide special mod_perl request handlers for remote
authentication and authorization requests. The response code in the header will
indicate if the user is authorized or not, or if they are allowed to view a
given resource
or not. Handlers would return XML or YAML containing the requested information,
the users ID, the session token and perhaps some digest key to verify the
response. I'd also like to configure the system so that any requests not comming
through SSL are refused.

On the back end the CAS server requires a set of tables in a relational
database. Since
this system is intended as a single point of maintenance of user data we can
control the schema. It would be nice if this could work with an LDAP server as
well as a MySQL (or other DBI supported relational database), or at least
be able to be configured to sync changes with an external system like LDAP so
that admins could have that information on a user (such as username, password,
full name, maybe UID etc) which is used elsewhere for system logins and such is
automatically synced.


=head2 RESPONSE CODES

	500	ERROR
	000	OK
	401	AUTH_REQUIRED
	403	FORBIDDEN

These values are drawn from Apache's response codes, since this system is
intended to be generally accessed via the Apache server. All call returns should
compare to these response codes (or to Apache::Constants codes, which these will
be maintained to match), not to the values. So, if $rc is the result of a call
to check_athorization, the correct usage would be:
if ($rc == ERROR) { error($message) }
elsif ($rc == OK) { do_something({}) }

A note on usage of return ERROR vs error(). error(), which basically calls
die(), is used for critical system problems, such as a missing configuration
file. The most common usage for error() is when there is a problem with a
database call. error()'s should almost never be seen in a well tested production
system since they generally occur because some argument was not validated or
handled properly (such as quoting names) or someting required by the system was
missing. ERROR's are returned to indicate there was a problem executing the
method for some reason, such as a required parameter was not provided.

See the
documentation for a specific method to determine what values it may return,
however the two most commonly returned are OK and FORBIDDEN. If a method is
expected to return someting beyond it's result code look in the second and
subsequent return values as the first will always be OK if the method suceeded.
The one exception to this rule are objects with accessor methods for attributes
which return that attributes value if present or undef if not.

FORBIDDEN is a rule-of-thumb default (for the moment anyway) for situations
where there were no ERROR's but the method needs to return a 'not OK' condition.
For example if validating a users new email address and all the required
parameters were provided, all the database calls worked, etc. but the email
address provided contained illegal characters, the FORBIDDEN code would be
returned.

Any time a staus code other than OK is returned, any relevant messages can be
retrieved by calling warning_notes() in list context.

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

B<TAG:> all

Yep, everything. ;-}

=cut

use 5.008000;
use strict;
use SQCAS::_config;
use Digest::MD5 qw(md5_hex);
use Carp qw(cluck confess croak carp);

# These are defined to match what I found in .../apache/httpd.h
# If these values change as defined in Apache, everything in the Apache/mod_perl
# space will break until these are updated to match
use constant ERROR => 500;
use constant OK => 000;
use constant AUTH_REQUIRED => 401;
use constant FORBIDDEN => 403;

require Exporter;
our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( exceptions => [ qw(error gripe warning_notes) ],
	rvals => [ qw(ERROR OK AUTH_REQUIRED FORBIDDEN) ],
	all => [ qw(error gripe ERROR OK AUTH_REQUIRED FORBIDDEN
		%CONFIG check_authorization check_authentication warning_notes) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

#our @EXPORT = qw(%CONFIG check_authorization check_authentication);


our $VERSION = '0.21';


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
 # domains that SQCAS services
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
	
	my $HR_allowed_params = {RESOURCE => $params{RESOURCE}, CLIENT => $client,
		DEBUG => $CONFIG{DEBUG}};
	$HR_allowed_params->{MATCHKEY} = $params{MATCHKEY}
		if exists $params{MATCHKEY};
	$HR_allowed_params->{MASK} = $params{MASK} if exists $params{MASK};
	unless ($CONFIG{DBH}->allowed($HR_allowed_params)) {
       	$CONFIG{ERRSTR} = "User for session $Qcookie not authorized to access "
			. "$params{RESOURCE}:\n\t" . $CONFIG{DBH}->error; 
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
    
	## NEED TO ADD CHECK FOR DISABLED USER!
	
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


=head2 error

Throw a fatal exeption. Returns a stack trace (confess) if called when
DEBUG is true. L<gripe> actually does all the work, error just tells
gripe to die.

=cut
sub error {
	gripe($_[0],1);
} # error

=head2 gripe

Generate debug sensitive warnings and exceptions. gripe also writes warnings
to a scratch pad in the calling object so that warning_notes method can
return all warnings generated. This behavior mirrors that of
L<DNAcore::WWW::Exceptions> for objects rather than CGI's.

Suggested debug level usage (as level goes up messages from earlier levels
should continue to be sent):

0:	Production. Perls warnings should _not_ be turned on and no debug
messages should be generated.

1:	Basic development level. Perls warnings are turned on. Basic debug
messages should be generated. Call confess to die. *

2:	Shotgun debugging. Code should now be generating debug messages when
entering and/or exiting important blocks so that program flow can be
observed. Now calls cluck for warn.

3:	Turns on Perls diagnostics. At this level messages should be generated for
every pass through loops. This would also be the appropriate level to dump
data structures at critical points. It is realistic to expect hundreds of
lines of output at _least_ at this level.

4:	Autodie - gripe will now throw a fatal exception with confess. Currently
this happens the first time called. However it realy should only happen
the first time a message not intended to be sent at levels 1-3 only.

* Usually debug statements are created during development or debugging calling
gripe with no if $DEBUG statement, and once a piece of code is working properly
an C<if $DEBUG >= n> statement is added tp the end, with n set to the
appropriate level as described above.

=cut
my @WARNINGS = ();
sub gripe {
	my $msg = shift || confess("error without message");
    my $die = shift || 0;
	
    my @call = caller;
    @call = caller(1) if $die;
	my $pkg = $call[0];
	
	my $debug = $CONFIG{DEBUG} || 0;
    $die = 1 if $debug > 3;
	
	# to make sure we know if this was generated here as oposed to SQCAS::Apache
	$msg = "SQCAS.pm: $msg" if $debug > 2;
	
	# just to be paranoid, we'll unlock table on fatal error
	if ($die && exists $CONFIG{DBH} && ref $CONFIG{DBH}) {
		$CONFIG{DBH}->do("UNLOCK TABLES");
	} # if dieing and DBH - make SURE tables have been unlocked
    
    $call[1] =~ s{.+/}{};
    $msg = "$call[1]" . "[$call[2]]: $msg";
	
	# record the warning - would be nice if trace could be captured without
	# eval, but haven't found a way to do that yet, and some messages fail
	# taint checks for eval.
	push(@WARNINGS,$msg);
    
    if ($die && $debug) { confess("$msg\n") } # if we're dying and debug is on
    elsif ($die) { croak("$msg\n") } # or die with just the message
    elsif ($debug > 1) { cluck("$msg\n") } # verbose warn
    else { carp("$msg\n") } # just let em know the basics
} # gripe


=head2 warning_notes

Returns any warnings stored in object from earliers calls to gripe. This is very
useful when warnings are not readily seen, such as when object is used from
a CGI and the errors are lost to the logs.

=cut
sub warning_notes {
	return (@WARNINGS);
} # warining_notes



1;

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -XAC -n SQCAS

=item 0.1

Initial code port.

=item 0.2

Basic required functionality for check auths in place. Apache auth handlers done
as well as simple Login handler. Core tests written and passing, user tests of
Apache handlers pass basic required functionality.

=item 0.21

User module functional and all basic methods in place. No automated tests for it
yet but that will be my next task before moving on to the Apache handlers for
registering a new user and a user view edit account handler. Also started
working on the docs.

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
