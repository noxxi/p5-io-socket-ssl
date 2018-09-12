#!perl

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
use IO::Select;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

$|=1;
print "1..21\n";


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
	SSL_verify_mode => 0,
	SSL_cert_file => "certs/client-cert.pem",
	SSL_key_file => "certs/client-key.enc",
	SSL_passwd_cb => sub { return "opossum" }
    )) {
	#DEBUG( $SSL_ERROR );
	print "not ";
    }
    ok( "sslify client" );

    UNIVERSAL::isa( $client,'IO::Socket::SSL' ) || print "not ";
    ok( 'client reblessed as IO::Socket::SSL' );

    $client->sock_certificate('subject') =~ /client\.local/ or print "not ";
    ok("client local certificate subject");
    $client->sock_certificate('issuer') =~ /IO::Socket::SSL Demo CA/ or print "not ";
    ok("client local certificate issuer");
    $client->get_fingerprint('sha256',$client->sock_certificate)
	eq 'sha256$f89986e895758f788a66d340bb3d849999c9ab7b7b14f23e67fb28226a4c4b2e'
	or print "not ";
    ok("client local certificate fingerprint");

    $client->peer_certificate('subject') =~ /server\.local/ or print "not ";
    ok("client peer certificate subject");
    $client->peer_certificate('issuer') =~ /IO::Socket::SSL Demo CA/ or print "not ";
    ok("client peer certificate issuer");
    $client->get_fingerprint()
	eq 'sha256$422658660b5e5f2a2c657d960e71a1b98a97158c728cdbd377076de8a0f1a568'
	or print "not ";
    ok("client peer certificate fingerprint");

    print $client "hannibal\n";

    exit;
}

my $csock = $server->accept || print "not ";
ok( "tcp accept" );


IO::Socket::SSL->start_SSL( $csock,
    SSL_server => 1,
    SSL_verify_mode => SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    SSL_ca_file => "certs/test-ca.pem",
    SSL_cert_file => "certs/server-cert.pem",
    SSL_key_file => "certs/server-key.enc",
    SSL_passwd_cb => sub { return "bluebell" },
) || print "not ";
#DEBUG( $IO::Socket::SSL::ERROR );
ok( 'sslify server' );

UNIVERSAL::isa( $csock,'IO::Socket::SSL' ) || print "not ";
ok( 'server reblessed as IO::Socket::SSL' );

$csock->sock_certificate('subject') =~ /server\.local/ or print "not ";
ok("server local certificate subject");
$csock->sock_certificate('issuer') =~ /IO::Socket::SSL Demo CA/ or print "not ";
ok("server local certificate issuer");
$csock->get_fingerprint('sha256',$csock->sock_certificate)
    eq 'sha256$422658660b5e5f2a2c657d960e71a1b98a97158c728cdbd377076de8a0f1a568'
    or print "not ";
ok("server local certificate fingerprint");

$csock->peer_certificate('subject') =~ /client\.local/ or print "not ";
ok("server peer certificate subject");
$csock->peer_certificate('issuer') =~ /IO::Socket::SSL Demo CA/ or print "not ";
ok("server peer certificate issuer");
$csock->get_fingerprint()
    eq 'sha256$f89986e895758f788a66d340bb3d849999c9ab7b7b14f23e67fb28226a4c4b2e'
    or print "not ";
ok("server peer certificate fingerprint");


my $l = <$csock>;
#DEBUG($l);
print "not " if $l ne "hannibal\n";
ok( "received client message" );

wait;



sub ok { print "ok #$_[0]\n"; }
