#!perl

use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

$|=1;
print "1..11\n";

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 2,
) || die "not ok # tcp listen failed: $!\n";
print "ok # tcp listen\n";
my $saddr = $server->sockhost.':'.$server->sockport;

defined( my $pid = fork() ) || die $!;
$pid ? server():client();
wait;
exit(0);


sub client {
    close($server);
    my $client = IO::Socket::INET->new($saddr) or
	die "not ok # client connect: $!\n";
    $client->autoflush;
    print "ok # client tcp connect\n";

    alarm(30);

    # Create first (outer) TLS layer
    syswrite($client,"start_outer\n");
    sleep(1); # avoid race condition
    IO::Socket::SSL->start_SSL($client,
	SSL_verify_mode => 0,
    ) || die "not ok # client::start_SSL outer: $SSL_ERROR\n";
    print "ok # client::start_SSL outer layer\n";

    ref($client) eq "IO::Socket::SSL" or print "not ";
    print "ok # client::class outer=".ref($client)."\n";

    # Read OK from server for outer layer
    my $n = sysread($client, my $buf, 1024);
    die "not ok # client read failed after outer: $!\n" unless $n;
    die "'$buf'" if $buf ne "OK_OUTER\n";
    print "ok # client received OK_OUTER\n";

    # Create second (inner) TLS layer on top of first using SSL_usebio
    syswrite($client,"start_inner\n");
    sleep(1); # avoid race condition
    $client = IO::Socket::SSL->start_SSL($client,
	SSL_verify_mode => 0,
	SSL_usebio => 1
    ) || die "not ok # client::start_SSL inner: $SSL_ERROR\n";
    print "ok # client::start_SSL inner layer\n";

    ref($client) eq "IO::Socket::SSL" or print "not ";
    print "ok # client::class inner=".ref($client)."\n";

    # Read OK from server for inner layer
    $n = sysread($client, $buf, 1024);
    die "not ok # client read failed after inner: $!\n" unless $n;
    die "'$buf'" if $buf ne "OK_INNER\n";
    print "ok # client received OK_INNER\n";

    # Test communication through double TLS layers
    syswrite($client,"HELLO\n");
    $n = sysread($client, $buf, 1024);
    die "not ok # client read failed for hello response: $!\n" unless $n;
    die "'$buf'" if $buf ne "WORLD\n";
    print "ok # client data exchange through double TLS\n";

    # Close connection
    $client->close || die "not ok # client::close\n";
    print "ok # client::close\n";
}

sub server {
    my $client = $server->accept || die $!;
    $client->autoflush;

    alarm(30);

    # Wait for signal to start outer TLS layer
    my $n = sysread($client, my $buf, 1024);
    die "not ok # server read failed for start_outer: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "start_outer";

    # Create first (outer) TLS layer
    IO::Socket::SSL->start_SSL( $client,
	SSL_server => 1,
	SSL_cert_file => "t/certs/client-cert.pem",
	SSL_key_file => "t/certs/client-key.pem",
    ) || die "not ok # server::start_SSL outer: $SSL_ERROR\n";

    ref($client) eq "IO::Socket::SSL" or print "not ";
    print "ok # server::class outer=".ref($client)."\n";

    syswrite($client,"OK_OUTER\n");

    # Wait for signal to start inner TLS layer
    $n = sysread($client, $buf, 1024);
    die "not ok # server read failed for start_inner: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "start_inner";

    # Create second (inner) TLS layer on top of first using SSL_usebio
    $client = IO::Socket::SSL->start_SSL( $client,
	SSL_server => 1,
	SSL_cert_file => "t/certs/server-cert.pem",
	SSL_key_file => "t/certs/server-key.pem",
	SSL_usebio => 1,
    ) || die "not ok # server::start_SSL inner: $SSL_ERROR\n";

    ref($client) eq "IO::Socket::SSL" or print "not ";
    print "ok # server::class inner=".ref($client)."\n";

    syswrite($client,"OK_INNER\n");

    # Test communication through double TLS layers
    $n = sysread($client, $buf, 1024);
    die "not ok # server read failed for hello: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "HELLO";
    syswrite($client,"WORLD\n");

    # Server closes gracefully
    $client->close || die "not ok # server::close\n";
    print "ok # server::close\n";
}
