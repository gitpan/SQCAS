# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 11;
use SQCAS qw(:all); # should have already passed tests
BEGIN { use_ok('SQCAS::Admin::User') };

#########################

# test simple load
my $user = SQCAS::Admin::User->load({ID => 1});
ok(ref $user eq 'SQCAS::Admin::User', 'Load user 1');

# test get_ autoload
my $email = $user->get_Email;
ok($email eq 'seanq@darwin.bu.edu','Autoloaded get_Email');

# test load fail
$user = SQCAS::Admin::User->load({ID => 5});
ok($user == ERROR, 'Fail to load non-existant user.');

# test new fail
$user = SQCAS::Admin::User->new({Username => 'Tester'});
ok($user == FORBIDDEN, 'Fail to create new user, password & email missing');

# test good new
$user = SQCAS::Admin::User->new({Username => 'Tester', Password => 'teesting',
	Email => 'sean@quinlan.org', DEBUG => 0});
ok(ref $user eq 'SQCAS::Admin::User', 'Create new user');

# test validate
my $valid = $user->validate_Firstname({Firstname => 'H@rry'});
ok($valid == FORBIDDEN, 'Invalid first name.');

# test set username refused
my $rc = $user->set_Username({Username => 'Toaster'});
ok($rc == ERROR, 'Refuse to alter Username.');

# test set password
$rc = $user->set_Password({Password => 'testing'});
ok($rc == OK, 'Reset password.');

# test autoload set
$rc = $user->set_Firstname({Firstname => 'Harry'});
ok($rc == OK, 'Set first name.');

# test disable
$rc = $user->disable;
ok($rc == OK, 'User disabled.');

# note subsequent tests will fail due to re-use of username and email
# DELETE FROM UserInfo WHERE Firstname = 'Harry';
# DELETE FROM Users WHERE Username = 'Tester';
