#!perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/core.t'

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

$|=1;
my $numtests = 35;
print "1..$numtests\n";

my @servers = map {
    IO::Socket::SSL->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Listen => 2,
	Timeout => 30,
	ReuseAddr => 1,
	SSL_key_file => "certs/server-key.enc",
	SSL_passwd_cb => sub { return "bluebell" },
	SSL_verify_mode => SSL_VERIFY_NONE,
	SSL_ca_file => "certs/test-ca.pem",
	SSL_cert_file => "certs/server-cert.pem",
    )
} (1..3);

if ( grep { !$_ } @servers > 0 ) {
    print "not ok # Server init\n";
    exit;
}
&ok("Server initialization");

my @saddr = map { $_->sockhost.':'.$_->sockport } @servers;
unless (fork) {
    @servers = ();
    my $ctx = IO::Socket::SSL::SSL_Context->new(
	 SSL_passwd_cb => sub { return "opossum" },
	 SSL_verify_mode => SSL_VERIFY_PEER,
	 SSL_ca_file => "certs/test-ca.pem",
	 SSL_ca_path => '',
	 SSL_session_cache_size => 4,
    );


    my $cache = $ctx->{session_cache} or do {
	print "not ok \# Context init\n";
	exit;
    };
    &ok("Context init");


    # Bogus session test
    unless ($cache->add_session("bogus", 0)) {
	print "not ";
    }
    &ok("Superficial Cache Addition Test");

    unless ($cache->add_session("bogus1", 0)) {
	print "not ";
    }
    &ok("Superficial Cache Addition Test 2");

    if (keys(%$cache) != 4) {
	print "not ";
    }
    &ok("Cache Keys Check 1");

    unless ($cache->{'bogus1'} and $cache->{'bogus'}) {
	print "not ";
    }
    &ok("Cache Keys Check 2");

    my ($bogus, $bogus1) = ($cache->{'bogus'}, $cache->{'bogus1'});
    unless ($cache->{'_head'} eq $bogus1) {
	print "not ";
    }
    &ok("Cache Head Check");

    unless ($bogus1->{prev} eq $bogus and
	    $bogus1->{next} eq $bogus and
	    $bogus->{prev} eq $bogus1 and
	    $bogus->{next} eq $bogus1) {
	print "not ";
    }
    &ok("Cache Link Check");


    IO::Socket::SSL::set_default_context($ctx);

    my $sock3 = IO::Socket::INET->new($saddr[2]);
    my @clients = (
	IO::Socket::SSL->new(PeerAddr => $saddr[0], Domain => AF_INET),
	IO::Socket::SSL->new(PeerAddr => $saddr[1], Domain => AF_INET),
	IO::Socket::SSL->start_SSL( $sock3 ),
    );

    if ( grep { !$_ } @clients >0 ) {
	print "not ok \# Client init $SSL_ERROR\n";
	exit;
    }
    &ok("Client init");

    # Make sure that first 'bogus' entry has been removed
    if (keys(%$cache) != 6) {
	warn Dumper($cache); use Data::Dumper;
	print "not ";
    }
    &ok("Cache Keys Check 3");

    if ($cache->{'bogus'}) {
	print "not ";
    }
    &ok("Cache Removal Test");

    if ($cache->{'_head'}->{prev} ne $bogus1) {
	print "not ";
    }
    &ok("Cache Tail Check");

    if ($cache->{'_head'} ne $cache->{$saddr[2]}) {
	print "not ";
    }
    &ok("Cache Insertion Test");

    for (0..2) {
	if (Net::SSLeay::get_session($clients[$_]->_get_ssl_object) ne
	    $cache->{$saddr[$_]}->{session}) {
	    print "not ";
	}
	&ok("Cache Entry Test $_");
	close $clients[$_];
    }

    @clients = map {
	IO::Socket::SSL->new(PeerAddr => $_, Domain => AF_INET)
    } @saddr;

    if (keys(%$cache) != 6) {
	print "not ";
    }
    &ok("Cache Keys Check 4");

    if (!$cache->{'bogus1'}) {
	print "not ";
    }
    &ok("Cache Keys Check 5");

    for (0..2) {
	if (Net::SSLeay::get_session($clients[$_]->_get_ssl_object) ne
	    $cache->{$saddr[$_]}->{session}) {
	    print "not ";
	}
	&ok("Second Cache Entry Test $_");
	unless ($clients[$_]->print("Test $_\n")) {
	    print "not ";
	}
	&ok("Write Test $_");
	unless ($clients[$_]->readline eq "Ok $_\n") {
	    print "not ";
	}
	&ok("Read Test $_");
	close $clients[$_];
    }

    exit(0);
}

my @clients = map { scalar $_->accept } @servers;
if ( grep { !$_ } @clients > 0 ) {
    print "not ok \# Client init\n";
    exit;
}
&ok("Client init");
close($_) for @clients;

@clients = map { scalar $_->accept } @servers;
if ( grep { !$_ } @clients > 0 ) {
    print $SSL_ERROR;
    print "not ok \# Client init 2\n";
    exit;
}
&ok("Client init 2");

for (0..2) {
    unless ($clients[$_]->readline eq "Test $_\n") {
	print "not ";
    }
    &ok("Server Read $_");
    unless ($clients[$_]->print("Ok $_\n")) {
	print "not ";
    }
    &ok("Server Write $_");
    close $clients[$_];
    close $servers[$_];
}

wait;


sub ok {
    print "ok #$_[0]\n";
}

sub bail {
	print "Bail Out! $IO::Socket::SSL::ERROR";
}
