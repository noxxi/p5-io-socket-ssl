#!/usr/bin/perl
# checks lots of https sites for OCSP problems
# https_ocsp_bulk  < list-of-sites.txt

use strict;
use warnings;
use IO::Socket::SSL 1.984;

# use a common OCSP cache for all
my $ocsp_cache = IO::Socket::SSL::OCSP_Cache->new(1000);

# load sites from file/stdin
# for top alexa sites see http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
while ( my $dst = <>) {

    # the domain can be somewhere on the line
    $dst = $dst =~m{\b([\w\-]+(\.[\w\-]+)+)\b} && $1 || do {
	warn "SKIP: no domain found in line: $dst";
	next;
    };

    # if the name is google.com try first www.google.com and if this 
    # fails google.com
    my @dst = ($dst);
    unshift @dst,"www.$dst" if $dst !~m{^www\.};
    my $cl;
    while (@dst && !$cl) {
	$dst = shift(@dst);
	$cl = IO::Socket::INET->new(
	    PeerHost => $dst,
	    PeerPort => 443,
	    Timeout => 5
	);
    }
    if (!$cl) {
	warn "SKIP: no connect to $dst\n";
	next;
    }


    warn "DEBUG: trying SSL upgrade on $dst\n";
    my $result;
    if ( IO::Socket::SSL->start_SSL($cl,
	SSL_hostname => $dst,
	SSL_verifycn_scheme => 'www',
	SSL_ocsp_mode => SSL_OCSP_FULL_CHAIN,
	SSL_ocsp_cache => $ocsp_cache,
    )) {
	warn "INFO: $dst got stapled response\n" if ${*$cl}{_SSL_ocsp_verify};
	my $r = $cl->ocsp_resolver;
	my %q = $r->requests;
	warn "DEBUG: $dst need ".keys(%q)." OCSP requests"
	    ." chain_size=".(0+$cl->peer_certificates)
	    ." URI=".  join(",",keys %q)."\n" 
	    if %q;
	$result = $r->resolve_blocking(timeout => 5);
	$result ||= 'ok';
	if ( my $s = $r->soft_error ) {
	    $result = "$result (soft: $s)";
	}
    } else {
	$result = $SSL_ERROR||$!;
    }
    warn "RESULT: $dst $result\n";
}

