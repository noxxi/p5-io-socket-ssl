#!perl -w
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl t/nonblock.t'


use Net::SSLeay;
use Socket;
use IO::Socket::SSL;
use IO::Select;
use Errno qw(EAGAIN EINPROGRESS );
use strict;

$|=1;
use vars qw( $SSL_SERVER_ADDR );
do "t/ssl_settings.req" || do "ssl_settings.req";

if ( ! getsize($$) ) {
	print "1..0 # Skipped: no usable ps\n";
	exit;
}

sub getsize {
	my $pid = shift;
	open( my $ps,'-|','ps','-o','size','-p',$pid ) or return;
	<$ps>; # header
	return int(<$ps>); # size
}

my $server = IO::Socket::SSL->new(
	LocalAddr => $SSL_SERVER_ADDR,
	Listen => 2,
	ReuseAddr => 1,
);

defined( my $pid = fork()) or do {
	print "1..0 # Skipped: fork failed\n";
	exit;
};

if ( $pid == 0 ) {
	# server
	while (1) {
		# socket accept, client handshake and client close 
		$server->accept
	}
	exit
}

close($server);
# plain non-SSL connect and close w/o sending data
IO::Socket::INET->new( $SSL_SERVER_ADDR ) for(1..100);
my $size100 = getsize($pid);
if ( ! $size100 ) {
	print "1..0 # Skipped: cannot get size of child process\n";
	exit
}

IO::Socket::INET->new( $SSL_SERVER_ADDR ) for(100..1000);
my $size1000 = getsize($pid);

print "1..1\n";
print "not " if $size100 != $size1000;
print "ok # check memleak failed handshake ($size100)\n";

kill(9,$pid);
wait;
exit
