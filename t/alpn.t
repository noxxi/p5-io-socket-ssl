#!perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/alpn.t'

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;

use Test::More;

# check if we have ALPN available
# if it is available
if ( ! IO::Socket::SSL->can_alpn ) {
    plan skip_all => "1..0 # Skipped: ALPN not available in Net::SSLeay\n";
}

# first create simple ssl-server
my $ID = 'server';
my $addr = '127.0.0.1';
my $server = IO::Socket::SSL->new(
    LocalAddr => $addr,
    Listen => 2,
    SSL_cert_file => 'certs/server-cert.pem',
    SSL_key_file => 'certs/server-key.pem',
    SSL_alpn_protocols => [qw(one two)],
) || do {
    plan skip_all => "$!";
};
ok(1,"Server Initialization at $addr");

# add server port to addr
$addr = "$addr:".$server->sockport;
print "# server at $addr\n";

my $pid = fork();
if ( !defined $pid ) {
    die $!; # fork failed

} elsif ( !$pid ) {    ###### Client

    $ID = 'client';
    close($server);
    my $to_server = IO::Socket::SSL->new(
	PeerHost => $addr,
	SSL_verify_mode => 0,
	SSL_alpn_protocols => [qw(two three)],
    ) or do {
        plan skip_all => "connect failed: ".IO::Socket::SSL->errstr();
    };
    ok(1,"client connected" );
    my $proto = $to_server->alpn_selected;
    is($proto, "two","negotiated $proto");
} else {                ###### Server
    my $to_client = $server->accept or do {
        kill(9,$pid);
        exit;
    };
    ok(1,"Server accepted" );
    my $proto = $to_client->alpn_selected;
    is($proto, "two","negotiated $proto");
    wait;
}
