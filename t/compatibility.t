#!perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/compatibility.t'

use strict;
use warnings;
use IO::Socket::SSL;
use Socket;

$|=1;

foreach ($^O) {
    if (/MacOS/ or /VOS/ or /vmesa/ or /riscos/ or /amigaos/) {
	print "1..0 # Skipped: fork not implemented on this platform\n";
	exit;
    }
}

$SIG{'CHLD'} = "IGNORE";

print "1..9\n";
IO::Socket::SSL::context_init(SSL_verify_mode => 0x01, SSL_version => 'TLSv1' );


my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 1,
) or do {
    print "Bail out! ";
    print("Setup of test IO::Socket::INET client and server failed.  All the rest of ",
	  "the tests in this suite will fail also unless you change the values in ",
	  "ssl_settings.req in the t/ directory.");
    exit;
};
print "ok # server create\n";

{
    package MyClass;
    use IO::Socket::SSL;
    our @ISA = "IO::Socket::SSL";
}

my $saddr = $server->sockhost.':'.$server->sockport;
unless (fork) {
    close $server;
    my $client = IO::Socket::INET->new($saddr);
    MyClass->start_SSL($client, SSL_verify_mode => 0) || print "not ";
    print "ok # ssl upgrade\n";
    (ref($client) eq "MyClass") || print "not ";
    print "ok # class MyClass\n";
    $client->issuer_name || print "not ";
    print "ok # issuer_name\n";
    $client->subject_name || print "not ";
    print "ok # subject_name\n";
    $client->opened || print "not ";
    print "ok # opened\n";
    print $client "Ok to close\n";
    close $client;
    exit(0);
}

my $contact = $server->accept;
IO::Socket::SSL::socketToSSL($contact, {
    SSL_server => 1,
    SSL_verify_mode => 0,
    SSL_cert_file => 'certs/server-cert.pem',
    SSL_key_file => 'certs/server-key.pem',
}) || print "not ";
print "ok # socketToSSL\n";
<$contact>;
close $contact;
close $server;

bless $contact, "MyClass";
print "not " if IO::Socket::SSL::socket_to_SSL($contact, SSL_server => 1);
print "ok # socket_to_SSL\n";

print "not " unless (ref($contact) eq "MyClass");
print "ok # upgrade is MyClass\n";

sub bail {
    print "Bail Out! $IO::Socket::SSL::ERROR";
}
