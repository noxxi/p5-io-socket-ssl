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

my %hosts = qw( 
    www.google.com sha1$41373a43343a30323a41333a35443a36433a46423a43443a38343a33463a31383a35393a38463a37303a43313a32393a39463a44303a46333a3833
    www.live.com sha1$31303a43353a36453a45393a45323a41433a41463a32453a37373a43413a45423a37303a37323a42463a36353a32323a44443a37343a32323a4238
);

my $proxy = ( $ENV{https_proxy} || $ENV{http_proxy} || '' )
    =~m{^(?:\w+://)?([\w\-.:\[\]]+:\d+)/?$} && $1;

my @cap = ('SSL_verifycn_name');
push @cap, 'SSL_hostname' if IO::Socket::SSL->can_client_sni();
plan tests => (1+@cap)*keys(%hosts);

while ( my ($host,$fp) = each %hosts ) {
    SKIP: {
	# first check if we can connect at all
	my @cl;
	for my $cap ('fp',@cap,'noca') {
	    my $cl;
	    if ( ! $proxy ) {
		# direct connection
		$cl = $ipclass->new(
		    PeerAddr => $host,
		    PeerPort => 443,
		    Timeout => 15,
		)
	    } elsif ( $cl = $ipclass->new( 
		PeerAddr => $proxy, 
		Timeout => 15 
		)) {
		# try to establish tunnel via proxy with CONNECT
		my $reply = '';
		if ( eval {
		    local $SIG{ALRM} = sub { die "timed out" };
		    alarm(15);
		    print $cl "CONNECT $host:443 HTTP/1.0\r\n\r\n";
		    while (<$cl>) {	
			$reply .= $_;
			last if m{\A\r?\n\Z};
		    }
		    $reply =~m{\AHTTP/1\.[01] 200\b} or 
			die "unexpected response from proxy: $reply";
		}) {
		} else {
		    $cl = undef
		}
	    }
		
	    skip "cannot connect to $host:443 with $ipclass: $!",0+@cap 
		if ! $cl;
	    push @cl,$cl;
	}

	diag(int(@cl)." connections to $host ok");

	# check if we have SSL interception by comparing the fingerprint we get
	my $cl = shift(@cl);
	skip "ssl upgrade failed even without verification",1+@cap
	    if ! IO::Socket::SSL->start_SSL($cl, SSL_verify_mode => 0 );
	skip "fingerprint mismatch - probably SSL interception",1+@cap
	    if $cl->get_fingerprint('sha1') ne $fp;
	diag("fingerprint $host matches");

	for my $cap (@cap) {
	    my $cl = shift(@cl);
	    # try to upgrade with SSL using default CA path
	    if ( IO::Socket::SSL->start_SSL($cl,
		SSL_verify_mode => 1,
		SSL_verifycn_scheme => 'http',
		$cap => $host,
	    )) {
		pass("SSL upgrade $host with default CA and $cap");
	    } else {
		fail("SSL upgrade $host with default CA and $cap: $SSL_ERROR");
	    }
	}

	# it should fail when we use no default ca, even on OS X
	# https://hynek.me/articles/apple-openssl-verification-surprises/
	$cl = shift(@cl);
	if ( IO::Socket::SSL->start_SSL($cl, SSL_ca_file => \'' )) {
	    fail("SSL upgrade $host with no CA succeeded");
	} else {
	    pass("SSL upgrade $host with no CA failed");
	}

    }
}
