use strict;
use warnings;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

$|=1;
print "1..14\n";

my ($server,$saddr) = create_listen_socket();
ok( 'listening' );

# first try bad non-SSL client
my $srv = fork_sub( 'server' );
fd_grep_ok( 'Waiting', $srv );
my $cl = fork_sub( 'client_no_ssl' );
fd_grep_ok( 'Connect from',$srv );
fd_grep_ok( 'Connected', $cl );
fd_grep_ok( 'SSL Handshake FAILED', $srv );
killall();

# then use SSL client
$srv = fork_sub( 'server' );
fd_grep_ok( 'Waiting', $srv );
$cl = fork_sub( 'client_ssl' );
fd_grep_ok( 'Connect from',$srv );
fd_grep_ok( 'Connected', $cl );
fd_grep_ok( 'SSL Handshake OK', $srv );
fd_grep_ok( 'Hi!', $cl );
killall();


sub server {
	print "Waiting\n";
	my $client = $server->accept || die "accept failed: $!";
	print "Connect from ".$client->peerhost.':'.$client->peerport."\n";
	if ( IO::Socket::SSL->start_SSL( $client, SSL_server => 1, Timeout => 5 )) {
		print "SSL Handshake OK\n";
		print $client "Hi!\n";
	} else {
		print "SSL Handshake FAILED - $!\n"
	}
}

sub client_no_ssl {
	my $c = IO::Socket::INET->new( $saddr ) || die "connect failed: $!";
	print "Connected\n";
	while ( sysread( $c,my $buf,8000 )) {}
}

sub client_ssl {
	my $c = IO::Socket::SSL->new( $saddr ) || die "connect failed: $!";
	print "Connected\n";
	while ( sysread( $c,my $buf,8000 )) { print $buf }
}


