package SQCAS::Apache::NewUser;

=head1 NAME

SQCAS::Apache::NewUser - Perl extension for blah blah blah

=head1 SYNOPSIS

  use SQCAS::Apache::NewUser;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for SQCAS::Apache::NewUser.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for SQCAS::Apache::NewUser, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.

=cut

use 5.008;
use strict;
use warnings;
use CGI qw(:standard);
use SQCAS::Apache;
use SQCAS qw(:all);
use SQCAS::Admin::User;
use Apache::Constants qw(:common);
$ENV{PATH} = '';

our $VERSION = '0.4';

=head1 METHODS

=head2 B<handler()>

This handler generates the new user form.

=cut
sub handler {
	my $apache = shift;
	my $cgi = new CGI;
	my %params = $cgi->Vars;
	
	my $message = '';
	$params{myself} = $cgi->self_url;
	$params{myself} =~ s/\?.+//; # strip url encoded data
	
	if (! $params{State}) {
		make_form($cgi,\%params);
	} # if make form
	
	elsif ($params{State} eq 'Register My Account') {
		register($cgi,\%params);
	} # else if 
	
	elsif ($params{State} eq 'Clear Form') {
		make_form($cgi,{myself => $params{myself}});
	} # else if 
	
	elsif ($params{State} eq 'Help') {
		my $me = __FILE__;
		chdir '/tmp';
		
		my $warnings = warning_notes();
		
		print $cgi->header, $cgi->start_html("Help for SQCAS new user form");
		print $warnings;
		print `/usr/bin/pod2html $me`;
		print $cgi->end_html;
	} # else if 
	
	else { error("Can't determine how to handle $params{State}") }
	
	return OK;
} # handler


sub make_form {
	my $cgi = shift;
	my $HR_params = shift;
	
	my $warnings = warning_notes();
	
	print $cgi->header, $cgi->start_html("SQCAS new user form");
    print <<HTML;

There is a 15-minute inactivity period for this system.  If it expires, you 
must log in again. Each client using the SQCAS server may specify it's own
timeout, so check the messages when entering client systems.

$warnings
<FORM ACTION="$HR_params->{myself}" METHOD="post">

<HR>
<H3>Username and Password</H3>
<table border="0" width="100%">
 <tr><td width="25%" ALIGN="right">
  <B>Choose Your UserName:&nbsp;&nbsp;</B><br>
  <font size="-1">(5-12 characters)&nbsp;&nbsp;</font>
 </td><td width="75%">
  <B><INPUT NAME="Username" size="12" maxlength="12" value="$HR_params->{Username}"></B>
 </td></tr>
 
 <tr><td width="25%" ALIGN="right">
  <B>Choose Your Password:&nbsp;&nbsp;</B><br>
  <font size="-1">(6-16 characters case-sensitive, no spaces)&nbsp;&nbsp;</font>
 </td><td width="75%">
  <B><INPUT NAME="Password" type=password size="12" maxlength="16"></B>
 </td></tr>
 
 <tr><td width="25%" ALIGN="right">
  <B>Re-type Your Password:&nbsp;&nbsp;</B>
 </td><td width="75%">
  <B><INPUT NAME="Confirmpass" type=password size="12" maxlength="16"></B>
 </td></tr>
</table>

<H3>General Information</H3>

<table border="0" width="100%">
 <tr><td width="25%" ALIGN="right">
  <B>First Name:&nbsp;&nbsp;</B>
 </td><td width="75%">
  <INPUT NAME="Firstname" size="20" maxlength="20" value="$HR_params->{Firstname}">
 </td></tr>
 
 <tr><td width="25%" ALIGN="right">
  <B>Last Name:&nbsp;&nbsp;</B>
 </td><td width="75%">
  <INPUT NAME="Lastname" size="20" maxlength="30" value="$HR_params->{Lastname}">
 </td></tr>
 
 <tr><td width="25%" ALIGN="right">
  <b>Phone Number:&nbsp;&nbsp;</b>
 </td><td width="75%">
  <INPUT NAME="Phone" size="20" maxlength="20" value="$HR_params->{Phone}">
 </td></tr>
 
 <tr><td width="25%" ALIGN="right">
  <b>Email Address:&nbsp;&nbsp;</b>
 </td><td width="75%">
  <INPUT NAME="Email" size="35" maxlength="50" value="$HR_params->{Email}">
 </td></tr>
 
 <TR><TD width="25%" ALIGN="right">
  <B>Address, line 1:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="Address1" SIZE="50" MAXLENGTH="100" VALUE="$HR_params->{Address1}">
 </TD></TR>
  
 <TR><TD width="25%" ALIGN="right">
  <B>Address, line 2:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="Address2" SIZE="50" MAXLENGTH="100" VALUE="$HR_params->{Address2}">
 </TD></TR>
  
 <TR><TD width="25%" ALIGN="right">
  <B>City:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="City" SIZE="25" MAXLENGTH="30" VALUE="$HR_params->{City}">
 </TD></TR>
 
 <TR><TD width="25%" ALIGN="right">
  <B>State or Province:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="Province" SIZE="20" MAXLENGTH="20" VALUE="$HR_params->{Province}">
 </TD></TR>
 
 <TR><TD width="25%" ALIGN="right">
  <B>Country:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="Country" SIZE="25" MAXLENGTH="30" VALUE="$HR_params->{Country}">
 </TD></TR>
 
 <TR><TD width="25%" ALIGN="right">
  <B>ZIP:&nbsp;&nbsp;</B>
 </TD><TD WIDTH="75%">
  <INPUT NAME="Zip" SIZE="10" MAXLENGTH="10" VALUE="$HR_params->{Zip}">
 </TD></TR>
  
</table>

<BR>
<CENTER>
<INPUT TYPE="submit" VALUE="Register My Account" NAME="State">
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<INPUT TYPE="submit" VALUE="Help" NAME="State">
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<INPUT TYPE="Reset" VALUE="Clear Form">
<BR><BR>
</CENTER>

<HR>

</FORM>
<hr>

HTML
	
	print $cgi->end_html;

} # make_form


sub register {
	my $cgi = shift;
	my $HR_params = shift;
	
	unless ($HR_params->{Password} eq $HR_params->{Confirmpass}) {
		gripe("Sorry, your passwords do not match. Please re-enter.");
		$HR_params->{Password} = $HR_params->{Confirmpass} = '';
		make_form($cgi,$HR_params);
		return;
	} # unless the two passwords match
	
	my $user = new SQCAS::Admin::User($HR_params);
	unless (ref $user) { make_form($cgi,$HR_params) }
	
	my $warnings = warning_notes();
	
	print $cgi->header, $cgi->start_html("SQCAS new user form");
    print "$warnings\n<h1>Thank you for registering!</H1>\n";
	print $cgi->end_html;
	
	return;
} # register


#sub  {

#} # 


1;
__END__
# Below is stub documentation for your module. You'd better edit it!
=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Apache::NewUser

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Sean Quinlan, E<lt>seanq@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Sean Quinlan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
