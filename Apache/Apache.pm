package SQCAS::Apache;


=head1 NAME

SQCAS::Apache - Basic functions for SQCAS mod_perl handlers & CGI's

=head1 SYNOPSIS

  use SQCAS::Apache;

=head1 ABSTRACT

  This should be the abstract for SQCAS::Apache.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Export DEBUG sensitive error handeling, including logging and warnings.
Configures set_message from CGI::Carp

=head2 EXPORT

error, gripe, warning_notes

=cut

use 5.008;
use strict;
use Apache;
use CGI::Carp qw(fatalsToBrowser cluck confess croak carp set_message);
use CGI qw(:standard);


require Exporter;

# This begin block is only intended to cover critical exceptions
# throw when module use'd
BEGIN {
	sub handle_error {
        my $msg = shift || "No message - probable failure on load";
        print header(), start_html("Fatal error encountered");
		print h1("Fatal error encountered");
		print h2("Reason: $msg");
		my $warnings = warning_notes();
		print "All warnings:<BR>$warnings<BR>";
		print end_html();
    } # handle_errors
    set_message(\&handle_error);
} # BEGIN


our @ISA = qw(Exporter);
our @EXPORT = qw(error gripe warning_notes);
our $VERSION = '0.8';
our $APACHE = 0;

if ($ENV{MOD_PERL}) {
    $APACHE = Apache->request;
	die "Apache not responding? -$APACHE-" unless $APACHE->method;
	
	# OK, now most of the modules base DNAcore and get their exception
	# handeling from there - let's replace it with our web use version
	*SQCAS::gripe = *gripe;
	*SQCAS::error = *error;
	*SQCAS::warning_notes = *warning_notes;
} # if we're actually under mod_perl

=head2 error


=cut
sub error {
	my $self = shift;
    my $msg = $_[0] && ref($self) ? shift : $self;
	gripe($msg,1,1);
} # error

=head2 gripe

Generate debug sensitive warnings and exceptions. gripe also writes warnings
to Apaches note pad (C<$r->notes($tag => $msg)>) so that warning_notes method
can return all warnings generated..

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
my $Errors = 0;
sub gripe {
	my $self = shift;
    my $msg_in = $_[0] && ref($self) ? shift : $self;
	confess("error called without message") unless $msg_in && $msg_in ne 1;
	
	my $msg = $msg_in;
    my $die = shift || 0;
	
    # if gripe called from error, get who called error instead
#    my $call_depth = $die ? 1 : 0;
#	my @call = $die ? caller($call_depth) : caller($call_depth);
#	@call = caller($call_depth+1) if $call[1] =~ /WWW/;
	my @call = caller($die);
	
    my $pkg = $call[0];
    my $DEBUG = 0;
    { no strict;
    	my $dbg = ref($self) ? $self->{DEBUG} : 0;
		$DEBUG = $dbg || ${"${pkg}::DEBUG"} || 0;
    } # return strict
    $die = 1 if $DEBUG > 3;
 	
	# just to be paranoid, we'll unlock table on fatal error if we have access
	# to DBH
	if ($die && ref($self) && exists $self->{DBH} && ref $self->{DBH}) {
		$self->{DBH}->do("UNLOCK TABLES");
	} # if dieing and DBH - make SURE tables have been unlocked
   
    $Errors++;
    my $tag = "Error$Errors";
    $call[1] =~ s{.+/}{};
	$msg = "[$call[1]:$call[2]] $msg";
    my $trace = '';
	
    if ($DEBUG) {
		eval { confess($msg) };
		$trace = $@;
    } # capture trace
    
    if ($die && $DEBUG) {
#		$APACHE->notes($tag => $trace); # fatals to browser should get it there
		$APACHE->log_error("trace-> $trace");
		die "Fatal error:\n$trace\n";
	}
    elsif ($die) {
		$APACHE->log_error("\n$msg\n");
		die "Fatal error: $msg\n";
    } # time to die
    elsif ($DEBUG > 1) {
		$APACHE->notes($tag => $trace);
		$APACHE->warn("$trace\n")
	}
    else {
		$APACHE->notes($tag => $msg);
		$APACHE->warn("$msg\n");
	}
} # gripe - throw $DEBUG dependant exception, exiting on warning with very high verbosities

# See DNAcore::WWW::Exceptions from MGH for some ideas on storing errors in a
# database to they can be accessed elsewhere.
=head2 warning_notes

Returns all the warnings generated to date for this request. If called in
scalar context returns all the warnings as an HTML formatted warning message,
or an empty string if no warnings. This allows the return value of
warning_notes to be placed directly in response. If called in list context
returns a list of all the warning messages.

=cut
sub warning_notes {
	my $self = shift;
	
	# for some reason I have yet to pin down, once in a while Apache returns
	# nothing, instead of a reference to an empty hash.
	my $HRnotes = $APACHE->notes || {};
	
	my @errors = ();
	
	# I don't know why, but sometimes errors are not sequencially numbred!?!
    foreach my $key (keys %{$HRnotes}) {
		if ($key =~ /Error(\d+)/) {
			push(@errors,$1);
		} # if it looks like our error
	} # while examining notes
	my $err_cnt = @errors;
	unless ($err_cnt) { return wantarray ? () : '' }
	
	my $warnstr = "<P><FONT COLOR=\"red\"><B>$err_cnt Warnings generated:</B></FONT><BR>\n";
    my @msgs = ();
	foreach my $err_num (sort {$a <=> $b} @errors) {
        my $msg = $APACHE->notes("Error$err_num");
		warn "No message for error #$err_num" unless $msg;
		# try to make mod_perl registry stack trace readable
		$msg =~ s/Apache::ROOT\S+harvard_2eedu::cgi_2d/cgi-/gm;
		push(@msgs,$msg);
		$msg =~ s/\n/<BR>/gm;
		$msg =~ s/\t/&nbsp;&nbsp;&nbsp;&nbsp;/g;
        $warnstr .= "$msg<BR>";
    } # get all errors in notes
    $warnstr .= '</P>';
	
	return wantarray ? @msgs : $warnstr;
} # warning_notes


1;
__END__

=head1 TO DO

Add get_session_id from DNAcore::WWW (well, conceptually anyway) as
get_session_token.

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.22 with options

  -AXC
	-n
	SQCAS::Apache

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
