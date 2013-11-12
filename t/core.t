#!perl
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/core.t'

use strict;
use warnings;
use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
use Errno 'EAGAIN';

$|=1;
foreach ($^O) {
    if (/MacOS/ or /VOS/ or /vmesa/ or /riscos/ or /amigaos/) {
	print "1..0 # Skipped: fork not implemented on this platform\n";
	exit;
    }
}

my $CAN_NONBLOCK = $^O =~m{mswin32}i ? 0 : eval "use 5.006; use IO::Select; 1";
my $CAN_PEEK = &Net::SSLeay::OPENSSL_VERSION_NUMBER >= 0x0090601f;

my $numtests = 40;
$numtests+=5 if $CAN_NONBLOCK;
$numtests+=3 if $CAN_PEEK;

print "1..$numtests\n";

my $error_trapped = 0;
my $server = IO::Socket::SSL->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 2,
    Timeout => 30,
    ReuseAddr => 1,
    SSL_verify_mode => 0x00,
    SSL_ca_file => "certs/test-ca.pem",
    SSL_use_cert => 1,
    SSL_cert_file => "certs/client-cert.pem",
    SSL_version => 'TLSv1',
    SSL_cipher_list => 'HIGH:!aNULL',
    SSL_error_trap => sub {
	my $self = shift;
	print $self "This server is SSL only";
	$error_trapped = 1;
	$self->close;
    },
    SSL_key_file => "certs/client-key.enc",
    SSL_passwd_cb => sub { return "opossum" }
);

if (!$server) {
    print "not ok\n";
    exit;
}
&ok("Server Initialization");

print "not " if (!defined fileno($server));
&ok("Server Fileno Check");

my $saddr = $server->sockhost.':'.$server->sockport;


unless (fork) {
    close $server;
    my $client = IO::Socket::INET->new($saddr);
    print $client "Test\n";
    (<$client> eq "This server is SSL only") || print "not ";
    &ok("Client non-SSL connection");
    close $client;

    $client = IO::Socket::SSL->new(
	PeerAddr => $saddr,
	SSL_verify_mode => 0x01,
	SSL_ca_file => "certs/test-ca.pem",
	SSL_use_cert => 1,
	SSL_cert_file => "certs/server-cert.pem",
	SSL_version => 'TLSv1',
	SSL_cipher_list => 'HIGH',
	SSL_key_file => "certs/server-key.enc",
	SSL_passwd_cb => sub { return "bluebell" },
	SSL_verify_callback => \&verify_sub,
    );


    sub verify_sub {
	my ($ok, $ctx_store, $cert, $error) = @_;
	unless ($ok && $ctx_store && $cert && !$error)
	{ print("not ok #client failure\n") && exit; }
	($cert =~ /IO::Socket::SSL Demo CA/) || print "not";
	&ok("Client Verify-sub Check");
	return 1;
    }


    $client || (print("not ok #client failure\n") && exit);
    &ok("Client Initialization");

    $client->fileno() || print "not ";
    &ok("Client Fileno Check");

#    $client->untaint() if ($HAVE_SCALAR_UTIL);  # In the future...

    $client->dump_peer_certificate() || print "not ";
    &ok("Client Peer Certificate Check");

    $client->peer_certificate("issuer") || print "not ";
    &ok("Client Peer Certificate Issuer Check");

    $client->get_cipher() || print "not ";
    &ok("Client Cipher Check");

    $client->syswrite('00waaaanf00', 7, 2);

    if ($CAN_PEEK) {
	my $buffer;
	$client->read($buffer,2);
	print "not " if ($buffer ne 'ok');
	&ok("Client Peek Check");
    }

    $client->print("Test\n");
    $client->printf("\$%.2f\n%d\n%c\n%s", 1.0444442342, 4.0, ord("y"), "Test\nBeaver\nBeaver\n");
    shutdown($client, 1);

    my $buffer="\0\0aaaaaaaaaaaaaaaaaaaa";
    $client->sysread($buffer, 7, 2);
    print "not " if ($buffer ne "\0\0waaaanf");
    &ok("Client Sysread Check");


## The future...
#    if ($HAVE_SCALAR_UTIL) {
#       print "not " if (is_tainted($buffer));
#       &ok("client");
#    }

    my @array = $client->getline();
    print "not "  if (@array != 1 or $array[0] ne "Test\n");
    &ok("Client Getline Check");

    print "not " if ($client->getc ne "\$");
    &ok("Client Getc Check");

    @array = $client->getlines;
    print "not " if (@array != 6);
    &ok("Client Getlines Check 1");

    print "not " if ($array[0] != "1.04\n");
    &ok("Client Getlines Check 2");

    print "not " if ($array[1] ne "4\n");
    &ok("Client Getlines Check 3");

    print "not " if ($array[2] ne "y\n");
    &ok("Client Getlines Check 4");

    print "not " if (join("", @array[3..5]) ne "Test\nBeaver\nBeaver\n");
    &ok("Client Getlines Check 5");

    print "not " if (defined(<$client>));
    &ok("Client Finished Reading Check");

    $client->close(SSL_no_shutdown => 1);

    my $client_2 = IO::Socket::INET->new($saddr);
    print "not " if (!$client_2);
    &ok("Second Client Initialization");

    $client_2 = IO::Socket::SSL->new_from_fd($client_2->fileno, '+<>',
					     SSL_reuse_ctx => $client);
    print "not " if (!$client_2);
    &ok("Client Init from Fileno Check");
    $buffer = <$client_2>;

    print "not " unless ($buffer eq "Boojums\n");
    &ok("Client (fileno) Readline Check");
    $client_2->close(SSL_ctx_free => 1);

    if ($CAN_NONBLOCK) {
	my $client_3 = IO::Socket::SSL->new(
	    PeerAddr => $saddr,
	    SSL_verify_mode => 0x01,
	    SSL_version => 'TLSv1',
	    SSL_cipher_list => 'HIGH',
	    SSL_ca_file => "certs/test-ca.pem",
	    SSL_use_cert => 1,
	    SSL_cert_file => "certs/server-cert.pem",
	    SSL_key_file => "certs/server-key.enc",
	    SSL_passwd_cb => sub { return "bluebell" },
	    Blocking => 0,
	);

	print "not " if (!$client_3);
	&ok("Client Nonblocking Check 1");
	close $client_3;

	my $client_4 = IO::Socket::SSL->new(
	    PeerAddr => $saddr,
	    SSL_reuse_ctx => $client_3,
	    Blocking => 0
	);
	print "not " if (!$client_4);
	&ok("Client Nonblocking Check 2");
	$client_3->close(SSL_ctx_free => 1);
    }

    exit(0);
}

my $client = $server->accept;

$error_trapped or print "not ";
&ok("Server non-SSL Client Check");

if ($client && $client->opened) {
    print "not ok # client stayed alive!\n";
    exit;
}
&ok("Server Kill-client Check");

($client, my $peer) = $server->accept;
if (!$client) {
    print "not ok # no client\n";
    exit;
}
&ok("Server Client Accept Check");

print "not " unless defined $peer;
&ok("Accept returning peer address check.");


fileno($client) || print "not ";
&ok("Server Client Fileno Check");

my $buffer;

if ($CAN_PEEK) {
    $client->peek($buffer, 7, 2);
    print "not " if ($buffer ne "\0\0waaaanf");
    &ok("Server Peek Check");

    print "not " if ($client->pending() != 7);
    &ok("Server Pending Check");

    print $client "ok";
}





sysread($client, $buffer, 7, 2);
print "not " if ($buffer ne "\0\0waaaanf");
&ok("Server Sysread Check");


my @array = scalar <$client>;
print "not "  if ($array[0] ne "Test\n");
&ok("Server Getline Check");


print "not " if (getc($client) ne "\$");
&ok("Server Getc Check");


@array = <$client>;
print "not " if (@array != 6);
&ok("Server Getlines Check 1");

print "not " if ($array[0] != "1.04\n");
&ok("Server Getlines Check 2");

print "not " if ($array[1] ne "4\n");
&ok("Server Getlines Check 3");

print "not " if ($array[2] ne "y\n");
&ok("Server Getlines Check 4");

print "not " if (join("", @array[3..5]) ne "Test\nBeaver\nBeaver\n");
&ok("Server Getlines Check 5");


syswrite($client, '00waaaanf00', 7, 2);
print($client "Test\n");
printf $client "\$%.2f\n%d\n%c\n%s", (1.0444442342, 4.0, ord("y"), "Test\nBeaver\nBeaver\n");

close $client;

($client, $peer) = $server->accept;
&bail unless $client;
print "not " unless (inet_ntoa((unpack_sockaddr_in($peer))[1]) eq "127.0.0.1");
&ok("Peer address check");

if ($CAN_NONBLOCK) {
    $client->blocking(0);
    $client->read($buffer, 20, 0);
    print "not " if $SSL_ERROR != SSL_WANT_READ;
    &ok("Server Nonblocking Check 1");
}

print "not " unless ($client->opened);
&ok("Server Client Opened Check 1");

print $client "Boojums\n";

close($client);

${*$client}{'_SSL_opened'} = 1;
print "not " if ($client->opened);
&ok("Server Client Opened Check 2");
${*$client}{'_SSL_opened'} = 0;


if ($CAN_NONBLOCK) {
    $client = $server->accept;
    print "not " if (!$client->opened);
    &ok("Server Nonblocking Check 2");
    close $client;

    $server->blocking(0);
    IO::Select->new($server)->can_read(30);
    $client = $server->accept;
    while ( ! $client ) {
	#DEBUG( "$!,$SSL_ERROR" );
	if ( $! == EAGAIN ) {
	    if ( $SSL_ERROR == SSL_WANT_WRITE ) {
		IO::Select->new( $server->opening )->can_write(30);
	    } else {
		IO::Select->new( $server->opening )->can_read(30);
	    }
	} else {
	    last
	}
	$client = $server->accept;
    }

    print "not " unless ($client && $client->opened);
    &ok("Server Nonblocking Check 3");
    close $client;
}

$server->close(SSL_ctx_free => 1);
wait;

sub ok {
    print "ok #$_[0]\n";
}

sub bail {
	print "Bail Out! $IO::Socket::SSL::ERROR";
}

## The future....
#sub is_tainted {
#    my $arg = shift;
#    my $nada = substr($arg, 0, 0);
#    local $@;
#    eval {eval "# $nada"};
#    return length($@);
#}
