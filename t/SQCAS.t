# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl SQCAS.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 11;
BEGIN { use_ok('SQCAS') };

#########################
use SQCAS qw(:all);

# see the data section below for a set of inserts to use to initialize
# the test data in the database
my $ip = '192.168.1.50';

# test failed authentication invalid username
my $result = check_authentication({USER => 'foo', PASSWORD => 'testing',
	IP => $ip});
ok($result == AUTH_REQUIRED, 'Auth failed, invalid username');


# test failed authentication invalid password
$result = check_authentication({USER => 'seanq', PASSWORD => 'barbar',
	IP => $ip});
ok($result == AUTH_REQUIRED, 'Auth failed, invalid password');


# test authentication
($result, my $token) = check_authentication({USER => 'seanq',
	PASSWORD => 'testing', IP => $ip});
ok($result == OK, 'Sucesful log in');



# test failed authorization by client missing
$result = check_authorization({COOKIE => $token,
	RESOURCE => '/cgi-bin/test_admin', MASK => 8, IP => '192.168.1.150'});
ok($result == ERROR, 'No client');


# test failed authorization by ip
$result = check_authorization({COOKIE => $token, CLIENT => 1,
	RESOURCE => '/cgi-bin/test_admin', MASK => 8, IP => '192.168.1.150'});
ok($result == AUTH_REQUIRED, 'IP mismatch');


# test failed authorization - invalid or non-associated resource
$result = check_authorization({COOKIE => $token, CLIENT => 1,
	RESOURCE => '/cgi-bin/test_admin2', MASK => 8, IP => $ip});
ok($result == FORBIDDEN, 'Not authorized');


# test failed authorization - don't have requested permission
$result = check_authorization({COOKIE => $token, MatchKey => '001',
	RESOURCE => 'SQCAS.Clients.ID', MASK => 1, CLIENT => 1, IP => $ip});
ok($result == FORBIDDEN, 'Not authorized - Mask mismatch');


# test authorization
$result = check_authorization({COOKIE => $token, MatchKey => '001',
	RESOURCE => 'SQCAS.Clients.ID', MASK => 8, CLIENT => 1, IP => $ip});
ok($result == OK, 'Authorized');


# test authorization with client lookup in %CONFIG
$result = check_authorization({COOKIE => $token, MatchKey => '001',
	RESOURCE => 'SQCAS.Clients.ID', MASK => 8, IP => $ip,
	CLIENT => 'localhost'});
ok($result == OK, 'Authorized');


# test timeout
sleep(4);
$result = check_authorization({COOKIE => $token, TIMEOUT => 3,
	RESOURCE => '/cgi-bin/test_admin', MASK => 8, CLIENT => 1, IP => $ip});
ok($result == AUTH_REQUIRED, 'Valid auth - timed out');


__DATA__
INSERT INTO UserInfo (Firstname,Lastname,Email,City,State)
	VALUES ('Sean','Quinlan','seanq@darwin.bu.edu','Boston','MA');
INSERT INTO Users (User,Username,Password)
	VALUES (0000000001,'seanq','2#FwWyUD2DWHU');
INSERT INTO GroupInfo (GroupName,Owner,Description)
	VALUES ('CAS_admin',0000000001,
	'SQCAS administrative group. The owner of this group is functionally root.');
INSERT INTO Groups SET User=0000000001, GroupID=001;
INSERT INTO Clients (Name,Domain,Admin,Description)
	VALUES ('SQCAS Server','localhost',0000000001,
	'The SQCAS server domain. This defines the server as a "client" for the purpose of accessing the online server tools which, of course, require authentication.');
INSERT INTO Permissions (Client,User,Resource,MatchKey,Permissions)
	VALUES (001,0000000001,'SQCAS.Clients.ID','001',12);
INSERT INTO Permissions (Client,GroupID,Resource,Permissions)
	VALUES (001,001,'/cgi-bin/test_admin',8);
