package SQCAS::DB;

=head1 NAME

SQCAS::DB - DBI wrapper which adds a few SQCAS specific methods.

=head1 SYNOPSIS

  use SQCAS qw(:all);
  my $dbh = $CONFIG{DBH};

=head1 ABSTRACT

  Wraps the DBI module, extending the database handle with some SQCAS specific
  methods. This module is not intemded to be used directly - _config.pm
  makes the connection using paramters from the SQCAS.yaml configuration.

=head1 DESCRIPTION

Used by _config.pm to connect to the SQCAS servers database. The database
handle is avalable at $CONFIG{DBH}. Use this as you would normally use a DBI
database handle. The methods described below are extensions to the normal DBI
functionality.

=head2 EXPORT

None by default.

=head2 METHODS

=cut


use 5.008;
use strict;

use vars qw($AUTOLOAD);

our $VERSION = '0.4';
# how to keep ERROR & OK in sync with the rest of SQCAS?!?
use constant ERROR => 0;
use constant OK => 1;
use DBI;


# Use for error handling by caller
our $ERRSTR = '';

=head2 connectDB

Wrapper for DBI->connect. Mainly does some configuration checking and if the
connection attempt fails will try every three seconds ten times.

PARAMETERS:

user:	Username to connect to the database with.

password:	Password for user.

server:	Type of database server. Defaults to mysql.

host:	Host to connect to. Defaults to localhost.

=cut
sub connectDB {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
    my $user_name = $params{user} or die 'No username provided';
    my $password  = $params{password} or die 'No password provided';
    my $server    = $params{server} || 'mysql';
    my $host      = $params{host} || $ENV{DBHost} || 'localhost';
    my $db        = 'SQCAS';
	

    #handle params as nec. such as setting debug or changing env. variables
    my $DEBUG = $params{'DEBUG'} || 0;
    $^W++ if $DEBUG;
    (require diagnostics && import diagnostics) if $DEBUG >= 2;

    $self->{'_created'} = 1;
    $self->{'db'}       = $db;
    $self->{DEBUG}      = $DEBUG;  

    my $dsn = "DBI:$server:$db:$host";
    my $dbh = '';
    my $attemp_count = 1;
    my $atrb = $params{DBIconnectAttributes} || { PrintError => 1 };
	warn "DBI->connect($dsn,$user_name,$password,$atrb)\n" if $DEBUG >= 2;
	
    # connect to database
    CONNECT: {
	$dbh = DBI->connect($dsn,$user_name,$password,$atrb);
	unless ($dbh) {
	    warn "Have no connection to DB, retrying in 3";
	    sleep(3);
	    $attemp_count++;
	    redo CONNECT unless $attemp_count > 10;
	} # no connection
    } # CONNECT control block

    # die if fail - catch with eval
	die "Failed to get connection $dbh after $attemp_count tries: $DBI::errstr"
		unless $dbh;
	
    $self->{dbh} = $dbh;
	
	# OK, lets intenalize any other DB's provided, such as DBAdmin,
	# DBFooBar etc.
	foreach my $field (keys %params) {
		#warn("Setting DB's, field = $field\n");
		$self->{$field} = $params{$field}
			if $field =~ /DB$/;
		#warn("Set self->{$field} = $self->{$field}\n");
	} # foreach param

    return bless ($self,$class);

} # end of sub ConnectDB()


=head2 userdat

Returns a data structure containg info about user. Requires sessiontag.

	 	    Username     => $username,
			ID           => $id,
 		    Groups       => $AR_group_ids,
		    Group_Names  => $AR_group_names,
		    tag          => $tag,
		    Qtag         => $Qtag,
			FullName     => $name,
			UserInfo     => $HR_userinfo,
			Supplemental => $HR_supplemental

tag is the session tag (or cookie). Qtag is the db quoted tag string. UserInfo
is a hash of all the fields in the UserInfo table (except ID). Supplemental is
a hash of all the supplimental client tables in which the user appeared, the
values of which are hashes of the contents.

=cut

sub userdat {
	my $self = shift;
	my $tag  = shift;
	my %userdat = ();
	
	$ERRSTR  = '';

	my $Qtag = $$self{dbh}->quote($tag);
	$userdat{tag}  = $tag;
	$userdat{Qtag} = $Qtag;
	
	($userdat{ID}, $userdat{Username})
		= $self->{dbh}->selectrow_array("SELECT Users.User, Username
		FROM Session, Users WHERE ID = $Qtag AND Users.User = Session.User");
	if ($DBI::err) {
		$ERRSTR = "Can't get user information from session ID $Qtag: "
			. $DBI::errstr;
		return ERROR;
	} # if dbi error
	
	my $userID = $userdat{ID}; # for ease of use
	my $AR_groups = $self->{dbh}->selectall_arrayref("SELECT GroupID
		FROM Groups WHERE User = $userID");
	if ($DBI::err) {
		$ERRSTR = "Can't get group membership from user ID $userID: "
			. $DBI::errstr;
		return ERROR;
	} # if dbi error
	foreach my $ARow (@{$AR_groups}) { push(@ {$userdat{Groups}},$$ARow[0]) }

	unless (@ {$userdat{Groups}} && $userID) {
		$ERRSTR = "No user information found";
		return ERROR;
    } # no failures, did we get any returned values

	my $AR_gnames = $self->{dbh}->selectall_arrayref("SELECT GroupName
		FROM Groups, GroupInfo WHERE User = $userID
		AND GroupID = ID");
	if ($DBI::err) {
		$ERRSTR = "Can't get group membership from user ID $userID: "
			. $DBI::errstr;
		return ERROR;
	} # if dbi error
	foreach my $ARow (@{$AR_gnames}) {
		push(@ {$userdat{Group_Names}},$$ARow[0]);
	} # foreach

	$userdat{UserInfo} = $self->{dbh}->selectrow_hashref("SELECT *
		FROM UserInfo WHERE ID = $userID");
	if ($DBI::err) {
		$ERRSTR = "Can't get UserInfo from user ID $userID: $DBI::errstr";
		return ERROR;
	} # if dbi error
	$userdat{FullName} = $userdat{UserInfo}{Firstname} . ' '
		. $userdat{UserInfo}{Lastname};

	my $AR_client_tables
		= $self->{dbh}->selectall_arrayref("SELECT Supplemental_User_Table
			FROM Clients");
	if ($DBI::err) {
		$ERRSTR = "Problem getting client table list: $DBI::errstr";
		return ERROR;
	} # if dbi error
	
	foreach my $ARow (@{$AR_client_tables}) {
		next unless $$ARow[0];
		my $HR_sup_user_info = $self->{dbh}->selectrow_hashref("SELECT *
			FROM $$ARow[0] WHERE ID = $userID");
		if ($DBI::err) {
			$ERRSTR = "Problem getting user info from client table $$ARow[0]: "
				. $DBI::errstr;
			return ERROR;
		} # if dbi error
		
		$userdat{Supplemental}{$$ARow[0]} = $HR_sup_user_info;
	} # foreach client table
	
	$self->{userdat} = \%userdat;
	return %userdat;
} # end userdat




=head2 allowed

Does the user have the requested permission on the indicated resource. Return
value is true (actually returns the numeric value of the mask) if allowed, null
(uundef) if not, 0 on error. Call $DBH->error to see any error messages.

This method will check for permissions by both user id ad group memberships.
However it is important to remember that permission granted in any grants
permission, and individual user permision is checked first.

PARAMS:

USER: The userdat hash as returned by this module. Since the hash is stored in
the DBH object, this can be left out to use the same values as last returned.

RESOURCE: The resource we are checking. Could be a database table, a file (such
as a CGI or data archive), a port - whatever.

MATCHKEY: The key to match. If no key provided will use the wildcard.

CLIENT:	The client ID or domain from which this request is being made.

PERMISSIONS: What permision to check. This can be supplied as string or integer.
Values are read = 8, modify = 4, create = 2, delete = 1. To check for multiple
Permissions at once you will need to use the numeric notation, summing the
required Permissions. So to check for Read and Modify permision provide 12 as
the parameters value. Create refers to permision to create a new record which
uses the refered to resource as a foreign key, or is under the refered resource
'tree'.

MASK: Same as PERMISSIONS.

Examples:

 # can place orders using fund 8887-009500
 $DBH->allowed({USER => \%userdat, RESOURCE => 'DNAcoreAdmin.Fund',
	MATCHKEY => '8887,009500', PERMISSIONS => 2});

 # can view oligo OD QC tool CGI (using cached userdat hash)
 $DBH->allowed({RESOURCE => 'cgi-bin/synthesis/oligoOD', PERMISSIONS => 'read'});

 # can delete results file
 $DBH->allowed({RESOURCE => 'sequencing/results/MK453GF67.seq', MASK => 1,
	USER => \%userdat});

=cut
sub allowed {
	$ERRSTR = '';
	
	# get object and params
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $debug = exists $params{DEBUG} ? $params{DEBUG} : 0;
	
	# make sure we have required argumants
	unless ($params{USER}) {
		if (exists $self->{userdat}) {
			$params{USER} = $self->{userdat};
		} # use cached hash
		else {
			$ERRSTR = "No user data provided and none cached.";
			return ERROR;
		} # required
	} # userdat hash required
	
	unless ($params{RESOURCE}) {
		$ERRSTR = "Resource to check against is required.";
		return ERROR;
	} # RESOURCE  required
	
	unless ($params{CLIENT}) {
		$ERRSTR = "The client for which this resource applies is required.";
		return ERROR;
	} # RESOURCE  required
	elsif ($params{CLIENT} =~ /[^\d]/) {
		$ERRSTR = "The client provided ($params{CLIENT}) must be the numeric "
			. "DB ID.";
		return ERROR;
	} # else if client contains non-int value
	
	
	$params{MASK} ||= $params{PERMISSIONS};
	unless ($params{MASK}) {
		$ERRSTR = "Need to know what permission to compare against.";
		return ERROR;
	} # MASK required
	
	# handle optional text mask
	my %from_text_mask = (read => 8, modify => 4, create => 2, delete => 1);
	if ($params{MASK} !~ /^\d+$/) {
		unless ($from_text_mask{lc($params{MASK})}) {
			$ERRSTR = 'MASK must be either read, modify, create, or delete. '
				. 'Do not recognize ' . lc($params{MASK}) . '.';
			return ERROR;
		} # don't recognize
		$params{MASK} = $from_text_mask{lc($params{MASK})};
	} # convert text mask to int
	
	# prepare params for use in SQL
	$params{MATCHKEY} ||= '%';
	my $resource = $self->{dbh}->quote($params{RESOURCE});
	my $key = $self->{dbh}->quote($params{MATCHKEY});
	my $mask = $params{MASK};
	
	# check for permission by user id
	my $qr = "SELECT ModTime
		FROM Permissions
		WHERE Client = $params{CLIENT} AND User = $params{USER}{ID}
		AND Resource = $resource AND MatchKey LIKE $key
		AND (Permissions & $mask) = $mask";
	warn("User Query: $qr\n") if $debug;
	
	my $has_perm = $self->{dbh}->selectrow_array($qr);
    if ($DBI::err) {
		$ERRSTR = "Problem checking permission by user id: $DBI::errstr";
		return ERROR;
    } # if dbi error
	return $mask if $has_perm;
	
	# user did not have permision directly, now check if any groups
	# grant requested permission
	my $grp_set = "'" . join(",",@{$params{USER}{Groups}}) . "'";
	$qr = "SELECT ModTime
		FROM Permissions
		WHERE Client = $params{CLIENT} AND FIND_IN_SET(GroupID,$grp_set)
		AND Resource = $resource
		AND MatchKey LIKE $key AND (Permissions & $mask) = $mask";
	warn("Group Query: $qr\n") if $debug;
	
	$has_perm = $self->{dbh}->selectrow_array($qr);
	if ($DBI::err) {
		$ERRSTR = "Problem checking permission by group: $DBI::errstr";
		return ERROR;
	} # if dbi error
	return $mask if $has_perm;
	
	warn "got to end of allowed and got no permisions using mask $mask\n"
		if $debug;
	# nope - permission denied
	return '';
} # allowed


=head2 client_info

Returns a hash reference with the info from the clients table. Hash will have two
sets of top level keys. The first are the domains that the clients define with
the value being the client ID; this allows lookup of client IDs by the domains.
The second key set are the client IDs, with the values being the contents of the
Clients table for that client.

=cut
sub client_info {
	$ERRSTR = '';
	
	# get object and params
	my $self = shift;
	
	my $HR_clients = $self->{dbh}->selectall_hashref("SELECT * FROM Clients",
		'ID');
	if ($DBI::err) {
		$ERRSTR = "Problem geting client data: $DBI::errstr";
		return ERROR;
	} # if dbi error
	
	my %clients = ();
	foreach my $id (keys %{$HR_clients}) {
		delete $HR_clients->{$id}{ID};
		$clients{$HR_clients->{$id}{Domain}} = $id;
	} # for each client
	
	return \%clients;
} # client_info


=head2 enum_to_array

Sole argument is the 'DESC <Table_Name> <Field>' to be used. Sets error
if not an enum field. Returns a list of the possible enum (or set) values.

=cut
sub enum_to_array {
	$ERRSTR = '';
	
	# get object and params
	my $self = shift;
	my $desc_stmnt = shift;
	
	unless ($desc_stmnt =~ /^DESC [\w\.]+ \w+$/i) {
		$ERRSTR = "Description statement ($desc_stmnt) does not look correct";
		return ERROR;
	} # be strict about DB call
	
	my ($field,$enum) = $self->{dbh}->selectrow_array($desc_stmnt);
	if ($DBI::err) {
		$ERRSTR = "Problem getting description of field from '$desc_stmnt': "
			. $DBI::errstr;
		return ERROR;
	} # SQL problem
	unless ($enum =~ /^enum|^set/i) {
		$ERRSTR = "Feild described does not appear to be enum or set. "
			. "Type = $enum.";
		return ERROR;
	} # not parsable as enum
	
	(my $vals) = $enum =~ /\((.+)\)/;
	$vals =~ s/^'//;
	$vals =~ s/'$//;
	return split(/','/,$vals);
} # enum_to_array

=head2

Replaces use of $DBI::errstr and $DBI::err. Returns error string from extension
methods or $DBI::errstr as appropriate.

=cut
sub error {
    
    $ERRSTR ||= $DBI::errstr if $DBI::err;
    return $ERRSTR;

} # error


# If it gets to AUTOLOAD, we'll assume it's a DBI method and hand it off
sub AUTOLOAD {
    my $self = shift;
    my $program = $AUTOLOAD;
    $ERRSTR = '';
    $program =~ s/.*:://;
	
    return $self->{dbh}->$program(@_);
} # AUTOLOAD


# this really neads to be called explicitly from a child handler under mod_perl
sub DESTROY {
    my $self = shift;
    #warn "In DB::DESTROY";

    if ($self->{dbh} && $$self{dbh}->ping) {
		$self->{dbh}->do("UNLOCK TABLES");
		$self->{dbh}->disconnect;
    } # if we have a database handle

} # object cleanup

1;
__END__

=head1 TO DO

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::DB

=item 0.4

All the basic SQCAS required functions in place and working.

=back


=head1 SEE ALSO

L<DBI>

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@darwin.bu.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
