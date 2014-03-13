use strict;
use warnings;
use Test::More;
use IO::Socket::SSL;

my $ipclass = 'IO::Socket::INET';
for( qw( IO::Socket::IP IO::Socket::INET6  )) {
    eval { require $_ } or next;
    $ipclass = $_;
    last;
}

my @hosts = qw( www.google.com www.live.com );
plan tests => 0+@hosts;

for my $host (@hosts) {
    SKIP: {
	# first check if we can connect at all
	my $cl = $ipclass->new( 
	    PeerAddr => $host,
	    PeerPort => 443,
	    Timeout => 15,
	);

	skip "cannot connect to $host:443 with $ipclass: $!",1
	    if ! $cl;
	diag("connection to $host ok");

	# then try to upgrade with SSL using default CA path
	my $upgrade_ok = IO::Socket::SSL->start_SSL($cl,
	    SSL_verify_mode => 1,
	    SSL_verifycn_name => $host,
	    SSL_verifycn_scheme => 'http',
	);
	ok($upgrade_ok,"SSL upgrade with default CA");
    }
}


    


