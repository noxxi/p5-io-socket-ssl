#!perl

use strict;
use warnings;
use Socket;
use IO::Socket::SSL;
use Test::More;

my $can_psk = IO::Socket::SSL->can_psk;
plan skip_all => 'insufficient support for PSK in Net::SSLeay'
    if !$can_psk || !$can_psk->{server} || !$can_psk->{client};

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    Listen => 2,
    ReuseAddr => 1,
) or die "\$!=$!, \$\@=$@";
my $saddr = $server->sockhost.':'.$server->sockport;

defined(my $server_pid = fork()) || die $!;
if ($server_pid == 0) {
    while (1) {
	my $cl = $server->accept or do {
	    diag("accept failed: $!, $SSL_ERROR");
	    next;
	};
	diag("tcp accept ok");

	IO::Socket::SSL->start_SSL($cl,
	    SSL_server => 1,
	    SSL_cipher_list => 'PSK',
	    SSL_psk => {
		'foo' => 'foobar',
		'io_socket_ssl' => 'barfoot',
		'' => pack("H*",'deadbeef'),
	    }
	) or do {
	    diag("start_SSL failed: \$\@=$@, S\$SSL_ERROR=$SSL_ERROR");
	    next;
	};
	diag("ssl accept ok");

	diag("client accepted: ver=".$cl->get_sslversion." cipher=".$cl->get_cipher);
	my $l = <$cl>;
	$l eq "ping\n" or die "wrong message from client: '$l'";
	print $cl "pong\n";
    }
    exit;
}
close($server);

for my $v ('TLSv1_3','TLSv1_2') {
    my $ctx = IO::Socket::SSL::SSL_Context->new(SSL_version => $v) or do {
	diag("no support for $v");
	next;
    };

    for my $t (
	[ 1, [ foo => 'foobar' ] ],
	[ 0, [ foo => 'barfoot' ] ],
	[ 1, [ io_socket_ssl => 'barfoot' ] ],
	[ 1, 'barfoot' ],
	[ 0, [ yikes => 'barfoot' ] ],
	[ 1, [ yikes => pack("H*",'deadbeef') ] ],
	[ 0, [ foo => pack("H*",'deadbeef') ] ],
    ) {
	my ($expect_ok,$psk) = @$t;
	my $tid = ref($psk) ? "$v/['$psk->[0]','$psk->[1]']":"$v/'$psk'";
	my $cl = IO::Socket::INET->new(
	    PeerAddr => $saddr
	) or die "tcp connect failed";
	$cl = IO::Socket::SSL->start_SSL($cl,
	    SSL_version => $v,
	    SSL_cipher_list => 'PSK',
	    SSL_psk => $psk
	);
	ok($expect_ok ? $cl : !$cl, "$tid - connect");
	next if !$cl or !$expect_ok;
	print $cl "ping\n";
	my $l = <$cl>;
	is($l, "pong\n", "$tid - data exchange");
    }
}

kill 9,$server_pid;
done_testing();
