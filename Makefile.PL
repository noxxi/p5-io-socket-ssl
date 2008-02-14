#
# a MakeMaker script for IO::Socket::SSL (aspa@hip.fi).
#
# $Id: Makefile.PL,v 1.1 2000/07/04 10:09:57 aspa Exp $.
#

use 5.00503; # prior versions have problems with self-ties.
use ExtUtils::MakeMaker;


# Test to make sure that Net::SSLeay can be properly seeded!
unless (defined $ENV{EGD_PATH}) {
    foreach (qw(/var/run/egd-pool /dev/egd-pool /etc/egd-pool
		/etc/entropy)) {
	if (-S) { $ENV{EGD_PATH}=$_; last }
    }
}

$| = 1;

{
    # issue warning, if Net::SSLeay cannot find random generator
    # redefine __WARN__ only locally to allow detection of failures
    # in PREREQ_PM
    local $SIG{__WARN__} = sub {
	undef $SIG{__WARN__};
	my $warning  = shift;
	return unless $warning =~ /random/i;
	print "Net::SSLeay could not find a random number generator on\n";
	print "your system.  This will likely cause most of the tests\n";
	print "to fail.  Please see the README file for more information.\n";
	print "the message from Net::SSLeay was: $warning\n";

	# Taken from ExtUtils::MakeMaker 6.16 (Michael Schwern) so that 
	# the prompt() function can be emulated for older versions of ExtUtils::MakeMaker.
	my $isa_tty = -t STDIN && (-t STDOUT || !(-f STDOUT || -c STDOUT));
	
	if ($isa_tty) {
	    print "Do you REALLY want to continue? [Default: no] ";
	    die "User cancelled install!\n" if (<STDIN> !~ /^y(?:es)?$/);
	} else {
	    die "Install cancelled.\n";
	}
    };

    if (! defined $ENV{SKIP_RNG_TEST}) {
	eval { require Net::SSLeay; $Net::SSLeay::trace=1; Net::SSLeay::randomize(); };
	die $@ if $@ =~ /cancelled/;
    } else {
	print "Random Number Generator test skipped.\n";
    }
}

{
    # make sure that we have dualvar from the XS Version of Scalar::Util
    if ( eval { require Scalar::Util } ) {
	eval { Scalar::Util::dualvar( 0,'' ) };
    	die "You need the XS Version of Scalar::Util for dualvar() support" 
	    if $@
    }
}

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
  'NAME'	=> 'IO::Socket::SSL',
  'AUTHOR'      => 'Steffen Ullrich & Peter Behroozi & Marko Asplund',
  'ABSTRACT'    => 'Nearly transparent SSL encapsulation for IO::Socket::INET.',
  'VERSION_FROM' => 'SSL.pm',
  'DISTNAME' => 'IO-Socket-SSL',
  'PREREQ_PM' => { 'Net::SSLeay' => 1.21, 'Scalar::Util' => 0 },
  'dist' => { COMPRESS => 'gzip', SUFFIX => 'gz', },
  'NO_META' => 1,
);
