#!perl

use strict;
use warnings;
use IO::Socket::INET;
use IO::Socket::SSL;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

$|=1;
print "1..16\n";

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
    my $tcp = IO::Socket::INET->new($saddr) or
	die "not ok # client connect: $!\n";
    $tcp->autoflush;
    print "ok # client tcp connect\n";

    alarm(30);

    # Create first (outer) TLS layer
    syswrite($tcp,"start_outer\n");
    sleep(1); # avoid race condition
    my $outer = IO::Socket::SSL->start_SSL($tcp,
	SSL_verify_mode => 0,
    ) || die "not ok # client::start_SSL outer: $SSL_ERROR\n";
    print "ok # client::start_SSL outer layer\n";

    ref($outer) eq "IO::Socket::SSL" or print "not ";
    print "ok # client::class outer=".ref($outer)."\n";

    # Verify outer layer certificate
    my $subj = $outer->peer_certificate('subject');
    $subj eq '/CN=client.local' or print "not ";
    print "ok # client::outer certificate subject=$subj\n";

    # Read OK from server for outer layer
    my $n = sysread($outer, my $buf, 1024);
    die "not ok # client read failed after outer: $!\n" unless $n;
    die "'$buf'" if $buf ne "OK_OUTER\n";
    print "ok # client received OK_OUTER\n";

    # Create second (inner) TLS layer on top of first using SSL_usebio
    syswrite($outer,"start_inner\n");
    sleep(1); # avoid race condition
    my $inner = IO::Socket::SSL->start_SSL($outer,
	SSL_verify_mode => 0,
	SSL_usebio => 1
    ) || die "not ok # client::start_SSL inner: $SSL_ERROR\n";
    print "ok # client::start_SSL inner layer\n";

    ref($inner) eq "IO::Socket::SSL" or print "not ";
    print "ok # client::class inner=".ref($inner)."\n";

    # Verify inner layer certificate
    $subj = $inner->peer_certificate('subject');
    $subj eq '/CN=server.local' or print "not ";
    print "ok # client::inner certificate subject=$subj\n";

    # Read OK from server for inner layer
    $n = sysread($inner, $buf, 1024);
    die "not ok # client read failed after inner: $!\n" unless $n;
    die "'$buf'" if $buf ne "OK_INNER\n";
    print "ok # client received OK_INNER\n";

    # Test communication through double TLS layers
    syswrite($inner,"HELLO\n");
    $n = sysread($inner, $buf, 1024);
    die "not ok # client read failed for hello response: $!\n" unless $n;
    die "'$buf'" if $buf ne "WORLD\n";
    print "ok # client data exchange through double TLS\n";

    <$inner>; # wait for EOF from server
}

sub server {
    my $tcp = $server->accept || die $!;
    $tcp->autoflush;

    alarm(30);

    # Wait for signal to start outer TLS layer
    my $n = sysread($tcp, my $buf, 1024);
    die "not ok # server read failed for start_outer: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "start_outer";

    # Create first (outer) TLS layer
    my $outer = IO::Socket::SSL->start_SSL( $tcp,
	SSL_server => 1,
	SSL_cert_file => "t/certs/client-cert.pem",
	SSL_key_file => "t/certs/client-key.pem",
    ) || die "not ok # server::start_SSL outer: $SSL_ERROR\n";

    ref($outer) eq "IO::Socket::SSL" or print "not ";
    print "ok # server::class outer=".ref($outer)."\n";

    # Verify outer layer peer certificate (client should have none with SSL_verify_mode => 0)
    my $subj = $outer->peer_certificate('subject') || '';
    $subj eq '' or print "not ";
    print "ok # server::outer peer certificate subject=$subj (expected empty)\n";

    syswrite($outer,"OK_OUTER\n");

    # Wait for signal to start inner TLS layer
    $n = sysread($outer, $buf, 1024);
    die "not ok # server read failed for start_inner: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "start_inner";

    # Create second (inner) TLS layer on top of first using SSL_usebio
    my $inner = IO::Socket::SSL->start_SSL( $outer,
	SSL_server => 1,
	SSL_cert_file => "t/certs/server-cert.pem",
	SSL_key_file => "t/certs/server-key.pem",
	SSL_usebio => 1,
    ) || die "not ok # server::start_SSL inner: $SSL_ERROR\n";

    ref($inner) eq "IO::Socket::SSL" or print "not ";
    print "ok # server::class inner=".ref($inner)."\n";

    # Verify inner layer peer certificate (client should have none with SSL_verify_mode => 0)
    $subj = $inner->peer_certificate('subject') || '';
    $subj eq '' or print "not ";
    print "ok # server::inner peer certificate subject=$subj (expected empty)\n";

    syswrite($inner,"OK_INNER\n");

    # Test communication through double TLS layers
    $n = sysread($inner, $buf, 1024);
    die "not ok # server read failed for hello: $!\n" unless $n;
    chomp($buf);
    die "'$buf'" if $buf ne "HELLO";
    syswrite($inner,"WORLD\n");

    # Server closes gracefully
    $inner->close || die "not ok # server::close\n";
    print "ok # server::close\n";
}
