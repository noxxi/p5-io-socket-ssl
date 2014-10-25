#!perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/nonblock.t'

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
use IO::Select;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

if ( ! eval "use 5.006; use IO::Select; return 1" ) {
    print "1..0 # Skipped: no support for nonblocking sockets\n";
    exit;
}

$|=1;
print "1..9\n";


my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 2,
);
print "not ok\n", exit if !$server;
ok("Server Initialization");

print "not " if (!defined fileno($server));
ok("Server Fileno Check");

my $saddr = $server->sockhost.':'.$server->sockport;
defined( my $pid = fork() ) || die $!;
if ( $pid == 0 ) {

    close($server);
    my $client = IO::Socket::INET->new($saddr) || print "not ";
    ok( "client tcp connect" );

    unless ( IO::Socket::SSL->start_SSL( $client,
	SSL_version => 'TLSv1',
	SSL_cipher_list => 'HIGH',
	SSL_verify_mode => 0,
	SSL_key_file => "certs/server-key.enc",
	SSL_passwd_cb => sub { return "bluebell" },
    )) {
	#DEBUG( $SSL_ERROR );
	print "not ";
    }
    ok( "sslify client" );

    UNIVERSAL::isa( $client,'IO::Socket::SSL' ) || print "not ";
    ok( 'client reblessed as IO::Socket::SSL' );

    print $client "hannibal\n";

    exit;
}

my $csock = $server->accept || print "not ";
ok( "tcp accept" );


IO::Socket::SSL->start_SSL( $csock,
    SSL_server => 1,
    SSL_verify_mode => 0x00,
    SSL_ca_file => "certs/test-ca.pem",
    SSL_cert_file => "certs/client-cert.pem",
    SSL_version => 'TLSv1',
    SSL_cipher_list => 'HIGH',
    SSL_key_file => "certs/client-key.enc",
    SSL_passwd_cb => sub { return "opossum" }
) || print "not ";
#DEBUG( $IO::Socket::SSL::ERROR );
ok( 'sslify server' );

UNIVERSAL::isa( $csock,'IO::Socket::SSL' ) || print "not ";
ok( 'server reblessed as IO::Socket::SSL' );

my $l = <$csock>;
#DEBUG($l);
print "not " if $l ne "hannibal\n";
ok( "received client message" );

wait;



sub ok { print "ok #$_[0]\n"; }
