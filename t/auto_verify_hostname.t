#!perl

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
use Test::More;

my $server = IO::Socket::SSL->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 2,
    ReuseAddr => 1,
    SSL_server => 1,
    SSL_cert_file => "certs/server-wildcard.pem",
    SSL_key_file => "certs/server-wildcard.pem",
);
warn "\$!=$!, \$\@=$@, S\$SSL_ERROR=$SSL_ERROR" if ! $server;
print "not ok\n", exit if !$server;
ok( $server, "Server Initialization");
my $saddr = $server->sockhost.':'.$server->sockport;

defined( my $pid = fork() ) || die $!;
if ( $pid == 0 ) {
    while (1) {
        my $csock = $server->accept || next;
        print $csock "hallo\n";
    }
}

close($server);
my @tests = qw(
    example.com      www FAIL
    server.local     ldap OK
    server.local     www FAIL
    bla.server.local www OK
    www7.other.local www OK
    www7.other.local ldap FAIL
    bla.server.local ldap OK
);

IO::Socket::SSL::default_ca('certs/test-ca.pem');
for( my $i=0;$i<@tests;$i+=3 ) {
    my ($name,$scheme,$result) = @tests[$i,$i+1,$i+2];
    my $cl = IO::Socket::SSL->new(
	PeerAddr => $saddr,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => $scheme,
	SSL_verifycn_name => $name,
    );
    if ( $result eq 'FAIL' ) {
       ok( !$cl, "connection to $name/$scheme failed" );
    } else {
       ok( $cl, "connection to $name/$scheme succeeded" );
    }
    $cl || next;
    like( <$cl>, qr/hallo\n/, "received hallo" );
}

for( my $i=0;$i<@tests;$i+=3 ) {
    my ($name,$scheme,$result) = @tests[$i,$i+1,$i+2];
    my $cl = IO::Socket::INET->new(
	PeerAddr => $saddr,
    ) || print "not ";
    ok( $cl, "tcp connect" );
    $cl = IO::Socket::SSL->start_SSL( $cl,
	SSL_verify_mode => 1,
	SSL_verifycn_scheme => $scheme,
	SSL_verifycn_name => $name,
    );
    if ( $result eq 'FAIL' ) {
        ok( !$cl, "ssl upgrade of connection to $name/$scheme failed" );
    } else {
        ok( $cl, "ssl upgrade of connection to $name/$scheme succeeded" );
    }
    $cl || next;
    like( <$cl>, qr/hallo\n/, "received hallo" );
}

kill(9,$pid);
wait;

done_testing();
