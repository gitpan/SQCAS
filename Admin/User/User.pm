package SQCAS::Admin::User;

=head1 NAME

SQCAS::Admin::User - Creates user objects for accessing and modifying user data.

=head1 SYNOPSIS

  use SQCAS::Admin::User;

  my $user = SQCAS::Admin::User->new(%userinfo);
  die "Couldn't create new user" if $user == ERROR;
  
  my $user = SQCAS::Admin::User->load({ID => 1234567654});
  die "Couldn't load user." if $user == ERROR;
  
Or even better error reporting where appropriate:

  if (! ref $user && $user == ERROR) {
    my @errors = warning_notes();
	die "Failed to load user:\n\t" . join("\n\t",@errors) . "\n";
  } # if error

=head1 ABSTRACT

  Generate user objects for either new or existing users. The object returned
  is used to manage that users data, such as Password, Username, address, etc.

=head1 DESCRIPTION

Generate user objects for either new or existing users. The object returned
is used to manage that users data, such as Password, Username, address, etc.

Currently only the SQCAS core Users and UserInfo tables are handled. Some
handling of client user tables will be added once this is core part is
functional. Set, get and validate methods are provided for the core tables, for
the client tables only set and get are provided - it is the clients
responsibility to validate their specific user information.

=head2 EXPORT

None by default.

=cut

use 5.008;
use strict;
use SQCAS qw(:all);
use Mail::Sendmail;
our $AUTOLOAD = '';


our $VERSION = '0.6';

=head2 new

Creates user object for a user not yet registered in the SQCAS system. Invoking
this contructer will generate an object to use for validating new user
information and entering a user in the database. When invoked it requires a
Username and Password for the user, which will be validated. If those pass
validation the user is registered in the database and the object is returned.

This object can now be used to validate additional user data and add it to the
users record. It is highly recommended that you require the users First and Last
names and any contact information you want be provided with the Username,
Password, etc. and that you record all those (that validate) immediately after
getting the user object back.

Please note

PARAMETERS:

Username: The Username the user will use for logging into the system. Usernames
are therefor unique in the database.

Password: The Password the user will use when logging in. It is highly
recommended you verify the Password before set it by having a user enter it
twice and compare the two entries.

Email:	An Email address for the user. This Email address will be used by the
system to send Emails to the user for important system notifications, such as
registration notification, systemwide administrative messages, etc. Since Email
addresses are required to be unique within the system, this also discourages
users from registering multiple times.

OPTIONS:

GROUP: The default initial group for the user. If not present the generic
'users' group will be used.

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = bless ({},$class);

	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	#handle params as nec. such as setting debug or changing env. variables
	my $debug = $params{DEBUG} || $CONFIG{DEBUG} || 0;
	$^W++ if $debug;
	(require diagnostics && import diagnostics) if $debug > 2;
	$self->{DEBUG} = $debug;
	
	
	error("No database connection!") unless $CONFIG{DBH}->ping;
	
	my $valid_Username = $self->validate_Username(%params);
	my $valid_Password = $self->validate_Password(%params);
	my $valid_Email    = $self->validate_Email(%params);
	
	unless ($valid_Username == OK && $valid_Password == OK
			&& $valid_Email == OK) {
		gripe("Username is unusable.") unless $valid_Username;
		gripe("Password is unusable.") unless $valid_Password;
		gripe("Email is unusable.") unless $valid_Email;
		return FORBIDDEN;
	} # Username or Password were invalid format
	
	# check to see if Username is already used
	my $Quser = $CONFIG{DBH}->quote($params{Username});
	my $already_used = $CONFIG{DBH}->selectrow_array("SELECT User FROM
		Users WHERE Username = $Quser");
	error('Problem checking if Username already used: '
		. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	gripe("Username $Quser is already used.") && return FORBIDDEN
		if ($already_used);
	
	# add user to database and set user ID in object
	my $QEmail = $CONFIG{DBH}->quote($params{Email});
	my $email_used = $CONFIG{DBH}->selectrow_array("SELECT ID
		FROM UserInfo WHERE Email = $QEmail");
	error('Problem checking if Email already used: '
		. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	gripe("Email $QEmail is already used. Perhaps you are already registered?")
		&& return FORBIDDEN if $email_used;
	
	# add any other user data provided
	my $set_vals = '';
	foreach my $field (%{$CONFIG{USER_INFO_FIELDS}}) {
		next if $field eq 'Email'; # already done
		if ($params{$field}) {
			my $validation_method = "validate_$field";
			my $is_valid = $self->$validation_method(%params);
			unless ($is_valid == OK) {
				gripe("Value for $field not accepted, please use EditAccount "
					. ' to add.');
				next;
			} # don't set invalid fields
			
			my $Qval = $CONFIG{DBH}->quote($params{$field});
			$set_vals .= ", $field = $Qval";
		} # if value for field provided
	} # for each possible field
	
	$CONFIG{DBH}->do("INSERT INTO UserInfo SET Email = $QEmail,
		regdate = CURRENT_DATE$set_vals");
	error('Problem entering users Email and generating User ID: '
		. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	my $id = $CONFIG{DBH}->selectrow_array("SELECT LAST_INSERT_ID()");
	error('No ID returned by database?!') unless $id;
	
	$self->{ID} = $id;
	$self->{Username} = $params{Username};
	
	my $QUsername = $CONFIG{DBH}->quote($params{Username});
	my $cryptpass = $self->crypt_pass($params{Password});
	my $Qpass = $CONFIG{DBH}->quote($cryptpass);
	$CONFIG{DBH}->do("INSERT INTO Users (User, Username, Password)
		VALUES ($id, $QUsername, $Qpass)");
	error('Problem registering user in the Users table: '
		. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	# add to default group
	$CONFIG{DBH}->do("INSERT INTO Groups VALUES ($id,$CONFIG{DEFAULT_GROUP})");
	error('Problem adding user to default group: '
		. $CONFIG{DBH}->error) if $CONFIG{DBH}->error;
	
	# add client specific user info
	
	
	return $self;
} # new


=head2 load

Returns a user object which can be used to access and update user data. Will
emit errors if fields that are expected not to be null (such as First Name)
are.

PARAMETERS:

ID:	The ID of the user.

or

Username:	The users unique Username.

=cut
sub load {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = bless ({},$class);
	
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	my $debug = $params{'DEBUG'} || $CONFIG{DEBUG} || 0;
	$^W++ if $debug;
	(require diagnostics && import diagnostics) if $debug > 2;
	$self->{DEBUG} = $debug;
	
	unless ($params{ID} || $params{Username}) {
		gripe("Either the user ID or Username are required.");
		return ERROR;
	} # unless unique identifier provided
	
	# get ID if Username provided
	if ($params{Username}) {
		my $Quser = $CONFIG{DBH}->quote($params{Username});
		$params{ID} = $CONFIG{DBH}->selectrow_array("SELECT User FROM
			Users WHERE Username = $Quser");
		error('Problem getting user id: ' . $CONFIG{DBH}->error)
			if $CONFIG{DBH}->error;
		
		gripe("Username $Quser not found in database.") && return ERROR
			unless $params{ID};
	} # if usename
	
	my $rc = $self->_fetch_user_data(%params);
	gripe('Problem loading user data.') && return ERROR if $rc == ERROR;
	
	$self->{ID} = $params{ID};
	return $self;
} # load


# populate self with user data - used to (re)load user data from db
sub _fetch_user_data {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	my $getdat = join(", ",keys %{$CONFIG{USER_INFO_FIELDS}});
	my $HR_userinfo = $CONFIG{DBH}->selectrow_hashref("SELECT $getdat
		FROM UserInfo WHERE ID = $params{ID}");
	error("Problem getting user info: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	gripe("No user info found for $params{ID}.") && return ERROR
		unless $HR_userinfo->{Email};
	
	map { $self->{$_} = $HR_userinfo->{$_} } keys %{$HR_userinfo};
		
	return OK
} # fetch_user_data


=head2 disable

Mark a user as diabled. Authentication will be denied.

=cut
sub disable {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	$CONFIG{DBH}->do("UPDATE Users SET Disabled = 'Yes'
		WHERE User = $self->{ID} LIMIT 1");
	error("Problem disabling user: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	return OK;
} # disable


=head2 enable

Reset disabled flag to 'No'.

=cut
sub enable {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	$CONFIG{DBH}->do("UPDATE Users SET Disabled = 'No'
		WHERE User = $self->{ID} LIMIT 1");
	error("Problem enabling user: " . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	return OK;
} # enable



=head2 Accessor, Mutator and Validation methods

Methods in this catagory are provided to access and alter the user data. The
following list describes the user attributes which these methods all work on.

=over 4

=item Username [A-Za-z0-9_'-.@]{5,50}

A textual key uniquely indicating one user. This value is supplied by the user
when they register and will function as the name with which they log in to the
system. This is usually a short login handle, such as the common first initial
last name combination (squinlan), however certain sites may wish to require
users to usa they're email address as a username. While the system allows
the use of an email address as a username, it is up to the client to modify the
user registration interface appropriately.

Once registered this field may I<not> be altered via set_Username.

=item Password [^;\s|><]{6,16}

A text string containing almost any plain ASCII non-whitespace text characters.
The system
can optionally require however that the password contain at least one upper
case, one lower case, one number and one non-alphanumeric character by setting
the optional STRICT parameter to true.

Please note that the plain password string is I<not> stored in the database.
Passwords are encrypted before they are stored in the databas.

=item Firstname [\w-' ]{2,20}

The users first name.

=item Lastname [\w-' ]{2,30}

The users last name.

=item Email [\w-.@]{6,50}

A valid email address for the user. The validation measures only examine the
email to see if it looks valid. However when a new user registers an email is
sent to the address provided with the from and reply-to fields set to the
client administrators email address, so they should recieve bounce
notifications.

=item Phone [\d-. )(]{3,20}

A contact phone number for the user.

=item Address1 [\w-.# ]{6,100}

The first address line to be used if a physical letter or package is to be sent
to the user.

=item Address2 [\w-.# ]{6,100}

The second address line to be used if a physical letter or package is to be
sent to the user.

=item City [\w-. ]{2,30}

The city for the users mailing address.

=item State [\w-.]{2,20}

The state for the users mailing address.

=item Country [\w-. ]{2,30}

The country for the users mailing address.

=item Zip [0-9-]{5,10}

The users zip code.

=back

=head2 validate_ 

These methods make sure that the suplied information meets system requirements
most of which are not enforced by the database. Such as forbidding certain
characters or requiring a minimum length. If the specific data is determined
to be 'invalid' then the FORBIDDEN staus code is returned.

All the set_ methods call validation before setting, so there is generally no
need to call the validation yourself unless you are setting multiple fields at
the same time and want them all handled in an all-or-nothing manner so want to
pre-validate them.

=cut
sub validate_Username {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	# we allow [@.-] to allow Emails to be used as Usernames
	(my @bad_characters) = $params{Username} =~ /([^\w'-.@]+)/g;
	if (@bad_characters) {
		gripe("Username contains illegal characters (@bad_characters)");
		$errors++;
	} # check for invalid characters
	
	if (length($params{Username}) < 5) {
		gripe("Username ($params{Username}) was missing or too short.");
		$errors++;
	} # Username too short
	
	elsif (length($params{Username}) > 50) {
		gripe("Username $params{Username}) was too long.");
		$errors++;
	} # Username too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Username


sub validate_Password {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_characters) = $params{Password} =~ /([;\s\|><]+)/g;
	if (@bad_characters) {
		gripe("Password contains illegal characters (@bad_characters)");
		$errors++;
	} # check for invalid characters
	
	if (length($params{Password}) > 16) {
		gripe("Password was too long.");
		$errors++;
	} # Password too long
	
	elsif (length($params{Password}) < 6) {
		gripe("Password was missing or too short.");
		$errors++;
	} # Password too short
	
	if ($params{STRICT}) {
		unless (   $params{Password} =~ /\d/
				&& $params{Password} =~ /[A-Z]/
				&& $params{Password} =~ /[a-z]/
				&& $params{Password} =~ /[^\w]/) {
			gripe("Password ($params{Password}) does not pass strict criteria.");
			$errors++;
		} # unless requirements met
	} # if 'strict' passwords required make sure a range of character types used

	return FORBIDDEN if $errors;
	return OK;
} # validate_Password


sub validate_Firstname {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_characters) = $params{Firstname} =~ /([^\w\-' ]+)/g;
	if (@bad_characters) {
		gripe("First Name contains invalid characters (@bad_characters).");
		$errors++;
	} # unless minimally valid
	
	if (length($params{Firstname}) < 2 || $params{Firstname} !~ /\w+/) {
		gripe('First Name appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Firstname}) > 20) {
		gripe('First Name appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Firstname


sub validate_Lastname {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
 	(my @bad_characters) = $params{Lastname} =~ /([^\w\-' ]+)/g;
	if (@bad_characters) {
		gripe("Last Name contains invalid characters (@bad_characters).");
		$errors++;
	} # unless minimally valid
	
	if (length($params{Lastname}) < 2 || $params{Lastname} !~ /\w+/) {
		gripe('Last Name appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Lastname}) > 30) {
		gripe('Last Name appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Lastname


sub validate_Phone {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_characters) = $params{Phone} =~ /([^\d\-. )(]+)/g;
	if (@bad_characters) {
		gripe("Phone # contains invalid characters (@bad_characters).");
		$errors++;
	} # unless phone # minimally valid
	
	if (length($params{Phone}) < 3 || $params{Phone} !~ /\d+/) {
		gripe('Phone Number appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Phone}) > 20) {
		gripe('Phone Number appears to be too long.');
		$errors++;
	} # field too long

	return FORBIDDEN if $errors;
	return OK;
} # validate_Phone


sub validate_Email {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_characters) = $params{Email} =~ /([^\w\-.\@]+)/g;
	if (@bad_characters) {
		gripe("Email contains invalid characters (@bad_characters).");
		$errors++;
	} # if bad characrters
	
	unless ($params{Email} =~ /\w+\@\w+\.\w{2}/) {
		gripe("Email provided does not appear to be a valid format.");
		$errors++;
	} # unless Email # minimally valid
	
	if (length($params{Email}) < 6 || $params{Email} !~ /\w{2}/) {
		gripe('Email Address appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Email}) > 50) {
		gripe('Email Address appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Email


sub validate_Address1 {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{Address1} =~ /([^\w\-.# ]+)/g;
	if (@bad_chars) {
		gripe("Address line 1 contains bad characters (@bad_chars).");
		$errors++;
	} # line contains bad characters
	
	if (length($params{Address1}) < 6 || $params{Address1} !~ /\w+/) {
		gripe('Address line 1 appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Address1}) > 100) {
		gripe('Address line 1 appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Address1


sub validate_Address2 {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{Address2} =~ /([^\w\-.# ]+)/g;
	if (@bad_chars) {
		gripe("Address line 2 contains bad characters (@bad_chars).");
		return ERROR;
	} # line contains bad characters
	
	if (length($params{Address2}) < 6 || $params{Address2} !~ /\w+/) {
		gripe('Address line 2 appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Address2}) > 100) {
		gripe('Address line 2 appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Address2


sub validate_City {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{City} =~ /([^\w\-. ]+)/g;
	if (@bad_chars) {
		gripe("City contains bad characters (@bad_chars).");
		return ERROR;
	} # line contains bad characters
	
	if (length($params{City}) < 2 || $params{City} !~ /\w+/) {
		gripe('City appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{City}) > 30) {
		gripe('City appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_City


sub validate_State {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{State} =~ /([^\w\-.]+)/g;
	if (@bad_chars) {
		gripe("State contains bad characters (@bad_chars).");
		return ERROR;
	} # line contains bad characters
	
	if (length($params{State}) < 2 || $params{State} !~ /\w+/) {
		gripe('State appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{State}) > 20) {
		gripe('State appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_State


sub validate_Country {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{Country} =~ /([^\w\-. ]+)/g;
	if (@bad_chars) {
		gripe("Country contains bad characters (@bad_chars).");
		return ERROR;
	} # line contains bad characters
	
	if (length($params{Country}) < 2 || $params{Country} !~ /\w+/) {
		gripe('Country appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Country}) > 30) {
		gripe('Country appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Country


sub validate_Zip {
	my $self = shift;
	my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	my $errors = 0;
	
	(my @bad_chars) = $params{Zip} =~ /([^[0-9]\-]+)/g;
	if (@bad_chars) {
		gripe("Zip contains bad characters (@bad_chars).");
		return ERROR;
	} # line contains bad characters
	
	if ($params{Zip} !~ /\d{5}/) {
		gripe('Zip appears to be missing or too short.');
		$errors++;
	} # field missing or too short
	elsif (length($params{Zip}) > 10) {
		gripe('Zip appears to be too long.');
		$errors++;
	} # field too long
	
	return FORBIDDEN if $errors;
	return OK;
} # validate_Zip


sub new_user_email {
	my $self = shift;
    my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	my @call = caller(1);
	$call[1] =~ s{.+/}{};
	my $name = $self->{Firstname} . ' ' . $self->{Lastname};
	
	my $message = <<BODY;
Central Authorization Server

New user $name registered with username $self->{Username}

This should have some boilerplate 'If you did not registered' yada yada

Mail generated for $call[1] by SQCAS::Admin::User V$VERSION

BODY
	
	my $from = $CONFIG{ADMIN_EMAIL};
	
	my %mail = (
		To      => $self->{Email},
		From    => $from,
		Message => $message,
		smtp    => 'molbio.mgh.harvard.edu',
		Subject => 'User registered to use fund at the MGH DNA core',
	);
	sendmail(%mail) or $self->error("Mail error: $Mail::Sendmail::error");
} # new_user_email


	
# Using autoload to handle accessors and mutators. Other methods as well?
# Should some values not be accessible or setable?
=head2 get_ methods

Returns the value of the attribute or undef.

=head2 set_ methods

Will validate the data provided and, if valid, update the field in the database.

=cut
sub set_Username {
	gripe('The username can not be altered');
	return ERROR;
} # set_Username


sub set_Password {
	my $self = shift;
    my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	
	error('No user ID found in self?!') unless $self->{ID};
	
	my $is_valid = $self->validate_Password(%params);
	unless ($is_valid == OK) {
		gripe('Password does not appear to be valid. Password in database '
			. 'unchanged.');
		return FORBIDDEN;
	} # don't set invalid password
	
	my $salt = $self->_get_salt;
	my $Qpass = $CONFIG{DBH}->quote(crypt($params{Password},$salt));
	$CONFIG{DBH}->do("UPDATE Users SET Password = $Qpass
		WHERE User = $self->{ID}");
	error('Problem updating password: ' . $CONFIG{DBH}->error)
		if $CONFIG{DBH}->error;
	
	return OK;
} # set_Password


sub crypt_pass {
    my $self   = shift;
    my $passwd = shift || '';
	
    my @salt  = ('a' .. 'z', 0 .. 9, '/', 'A' .. 'Z', '.');
	my $salt = join('', (@salt[int(rand($#salt)), int(rand($#salt))]));
	
	if ($passwd) {
		return crypt($passwd,$salt);
	} # if we were provided a password, just encrypt
	
    my @chars = ('*', '_', '-', @salt, '#', '!', '@');
    my $word;
    foreach (0 .. int(rand(2))+6) { $word .= $chars[int(rand($#chars))] };

    return ($word,crypt($word,$salt));
} # passgen


# only setting username and password need special handling and all the rest
# are in UserInfo
sub AUTOLOAD {
	my $self = shift;
    my %params = ref $_[0] eq "HASH" ? %{$_[0]} : @_;
	(my $method) = $AUTOLOAD =~ /::(\w+)$/;
	
	if ($AUTOLOAD =~ /::get_(\w+)$/) {
		my $attrib = $1;
		
		unless ($CONFIG{USER_INFO_FIELDS}{$attrib}) {
			gripe("$attrib does not appear to be a valid user attribute.");
			return ERROR;
		} # unless
		
		else { return exists $self->{$attrib} ? $self->{$attrib} : '' }
	} # accessor
	
	elsif ($AUTOLOAD =~ /::set_(\w+)$/) {
		my $attrib = $1;
		unless ($CONFIG{USER_INFO_FIELDS}{$attrib}) {
			gripe("$attrib does not appear to be a valid user attribute.");
			return ERROR;
		} # unless
		
		else {
			error('No user ID found in self?!') unless $self->{ID};
			
			my $validation_method = "validate_$attrib";
			my $is_valid = $self->$validation_method(%params);
			unless ($is_valid == OK) {
				gripe("$attrib does not appear to be valid. $attrib in "
					. 'database unchanged.');
				return FORBIDDEN;
			} # don't set invalid password
	
			my $Qval = $CONFIG{DBH}->quote($params{$attrib});
			$CONFIG{DBH}->do("UPDATE UserInfo SET $attrib = $Qval
				WHERE ID = $self->{ID}");
			error('Problem updating password: ' . $CONFIG{DBH}->error)
				if $CONFIG{DBH}->error;
			
			return OK;
		} # update field
	} # mutator
} # AUTOLOAD


1;
__END__

=head1 TO DO

If client id is provided data from the client table should also be loaded into
the user object.

Determine what additional address fields might be advisable. And if addresses
should be placed in a separate table to allow users to have multiple addresses.

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Admin::User

=item 0.2

Base adaption.

=item 0.21

new, load, validate, get an set methods in place as well as stub new user
email notification. Next come the tests.

=item 0.22

Added tests for user object and disable/enable methods. Small additions to docs.

=back



=head1 SEE ALSO

L<SQCAS>

http://bmerc-www.bu.edu/

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@darwin.bu.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
