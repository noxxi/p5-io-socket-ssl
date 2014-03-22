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
plan tests => 2*@hosts;

for my $host (@hosts) {
    SKIP: {
	# first check if we can connect at all
	my @cl;
	for(1,2) {
	    my $cl = $ipclass->new( 
		PeerAddr => $host,
		PeerPort => 443,
		Timeout => 15,
	    ) or last;
	    push @cl,$cl;
	}

	skip "cannot connect to $host:443 with $ipclass: $!",1
	    if ! @cl == 2;
	diag("connection to $host ok");

	# then try to upgrade with SSL using default CA path
	my $upgrade1 = IO::Socket::SSL->start_SSL($cl[0],
	    SSL_verify_mode => 1,
	    SSL_verifycn_name => $host,
	    SSL_verifycn_scheme => 'http',
	);
	ok($upgrade1,"SSL upgrade with default CA and SSL_verifycn_name");

	# use SSL_hostname instead of SSL_verifycn_name
	# this should do SNI and give a default for SSL_verifycn_name
	my $upgrade2 = IO::Socket::SSL->start_SSL($cl[1],
	    SSL_verify_mode => 1,
	    SSL_hostname => $host,
	    SSL_verifycn_scheme => 'http',
	);
	ok($upgrade2,"SSL upgrade with default CA and SSL_hostname");
    }
}


    


