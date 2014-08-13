#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use IO::Socket::SSL;

plan skip_all => "no OCSP support" if ! IO::Socket::SSL->can_ocsp;

#$Net::SSLeay::trace=3;

my @tests = (
    {
	# this should give us OCSP stapling
	host => 'www.live.com',
	port => 443,
	fingerprint => 'sha1$10c56ee9e2acaf2e77caeb7072bf6522dd7422b8',
	ocsp_staple => 1,
    },
    {
	# no OCSP stapling yet
	host => 'www.google.com',
	port => 443,
	fingerprint => 'sha1$007a5ab302f14446e2ea24d3a829de22ba1bf950',
    },
    {
	# this is revoked
	host => 'revoked.grc.com',
	port => 443,
	fingerprint => 'sha1$34703c40093461ad3ce087e161c7b7f42abe770c',
	expect_revoked => 1
    },
);

plan tests => 0+@tests;

my $timeout = 10;
my $proxy = ( $ENV{http_proxy} || '' )
    =~m{^(?:\w+://)?([\w\-.:\[\]]+:\d+)/?$} && $1;
my $have_httptiny = eval { require HTTP::Tiny };
my $ipclass = 'IO::Socket::INET';
for( qw( IO::Socket::IP IO::Socket::INET6  )) {
    eval { require $_ } or next;
    $ipclass = $_;
    last;
}


TEST:
for my $test (@tests) {
    my $tcp_connect = sub {
	if ( ! $proxy ) {
	    # direct connection
	    return $ipclass->new(
		PeerAddr => $test->{host},
		PeerPort => $test->{port},
		Timeout => $timeout,
	    ) || die "tcp connect to $test->{host}:$test->{port} failed: $!";
	}
	my $cl = $ipclass->new(
	    PeerAddr => $proxy,
	    Timeout => $timeout,
	) || die "tcp connect to proxy $proxy failed: $!";

	# try to establish tunnel via proxy with CONNECT
	{
	    local $SIG{ALRM} = sub { 
		die "proxy HTTP tunnel creation timed out" };
	    alarm($timeout);
	    print $cl "CONNECT $test->{host}:$test->{port} HTTP/1.0\r\n\r\n";
	    my $reply = '';
	    while (<$cl>) {
		$reply .= $_;
		last if m{\A\r?\n\Z};
	    }
	    alarm(0);
	    $reply =~m{\AHTTP/1\.[01] 200\b} or
		die "unexpected response from proxy: $reply";
	}
	return $cl;
    };

    SKIP: {
	# first check fingerprint in case of SSL interception
	my $cl = eval { &$tcp_connect } or skip "TCP connect#1 failed: $@",1;
	diag("tcp connect to $test->{host}:$test->{port} ok");
	skip "SSL upgrade w/o validation failed: $SSL_ERROR",1 
	    if ! IO::Socket::SSL->start_SSL($cl, SSL_verify_mode => 0);
	skip "fingerprints do not match",1
	    if $cl->get_fingerprint('sha1') ne $test->{fingerprint};
	diag("fingerprint matches");

	# then check if we can use the default CA path for successful
	# validation without OCSP yet
	$cl = eval { &$tcp_connect } or skip "TCP connect#2 failed: $@",1;
	skip "SSL upgrade w/o OCSP failed: $SSL_ERROR",1 
	    if ! IO::Socket::SSL->start_SSL($cl, SSL_ocsp_mode => SSL_OCSP_NO_STAPLE );
	diag("validation with default CA w/o OCSP ok");

	# check with default settings
	$cl = eval { &$tcp_connect } or skip "TCP connect#3 failed: $@",1;
	my $ok = IO::Socket::SSL->start_SSL($cl);
	if ($test->{expect_revoked}) {
	    if (!$ok && $SSL_ERROR =~m/revoked/) {
		pass("revoked within stapling as expected");
		next TEST;
	    } else {
		fail( $ok ? "expected revoked but connection ok" : 
		    "expected revoked, but $SSL_ERROR");
		next TEST;
	    }
	} elsif (!$ok) {
	    fail("SSL upgrade with OCSP stapling failed: $SSL_ERROR");
	    next TEST;
	}
	# we got usable stapling if _SSL_ocsp_verify is defined
	if ($test->{ocsp_staple}) {
	    if ( ! ${*$cl}{_SSL_ocsp_verify}) {
		fail("did not get expected OCSP response with stapling");
		next TEST;
	    } else {
		diag("got stapled response as expected");
	    }
	}

	goto done if ! $have_httptiny;

	# use OCSP resolver to resolve remaining certs, should be at most one
	my $ocsp_resolver = $cl->ocsp_resolver;
	my %rq = $ocsp_resolver->requests;
	if (keys(%rq)>1) {
	    fail("got more open OCSP requests (".keys(%rq).
		") than expected(1) in default mode");
	    next TEST;
	}
	my $err = $ocsp_resolver->resolve_blocking(timeout => $timeout);
	if ($test->{expect_revoked}) {
	    if ($err =~m/revoked/) {
		pass("revoked with explicit OCSP request as expected");
		next TEST;
	    } elsif ( $err =~m/status not yet valid/ ) {
		pass("temporary server side error with OCSP check: $err");
		next TEST;
	    } else {
		fail("expected revoked, but error=$err");
		next TEST;
	    }
	}
	diag("validation with default CA with OCSP defaults ok");

	# now check with full chain
	$cl = eval { &$tcp_connect } or skip "TCP connect#4 failed: $@",1;
	my $cache = IO::Socket::SSL::OCSP_Cache->new;
	if (! IO::Socket::SSL->start_SSL($cl, 
	    SSL_ocsp_mode => SSL_OCSP_FULL_CHAIN,
	    SSL_ocsp_cache => $cache
	)) {
	    skip "unexpected fail of SSL connect: $SSL_ERROR",1 
	}
	my $chain_size = $cl->peer_certificates;
	$ocsp_resolver = $cl->ocsp_resolver;
	# there should be no hard error after resolving - unless an intermediate
	# certificate got revoked which I don't hope
	$err = $ocsp_resolver->resolve_blocking(timeout => $timeout);
	if ($err) {
	    fail("fatal error in OCSP resolver: $err");
	    next TEST;
	}
	# we should now either have soft errors or the OCSP cache should have 
	# chain_size entries
	if ( ! $ocsp_resolver->soft_error ) {
	    my $cache_size = keys(%$cache)-1;
	    if ($cache_size!=$chain_size) {
		fail("cache_size($cache_size) != chain_size($chain_size)");
		next TEST;
	    }
	}
	diag("validation with default CA with OCSP full chain ok");

	done:
	pass("OCSP tests $test->{host}:$test->{port} ok");
    }
}

