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

my @cap = ('SSL_verifycn_name');
push @cap, 'SSL_hostname' if IO::Socket::SSL->can_client_sni();
plan tests => @cap*@hosts;

for my $host (@hosts) {
    SKIP: {
	# first check if we can connect at all
	my %cl;
	for my $cap (@cap) {
	    my $cl = $ipclass->new(
		PeerAddr => $host,
		PeerPort => 443,
		Timeout => 15,
	    );
	    skip "cannot connect to $host:443 with $ipclass: $!",1 if ! $cl;
	    $cl{$cap} = $cl;
	}

	diag("connection to $host ok");

	while ( my ($cap,$cl) = each %cl ) {
	    # then try to upgrade with SSL using default CA path
	    my $upgrade_cl = IO::Socket::SSL->start_SSL($cl,
		SSL_verify_mode => 1,
		SSL_verifycn_scheme => 'http',
		$cap => $host,
	    );
	    ok($upgrade_cl,"SSL upgrade with default CA and $cap");
	}
    }
}
