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
    www.google.com sha1$baa77df4ce1d50df3466f9258b2394f4c6c6c5b9
    www.yahoo.com sha1$764a19e1eb26917ef298cf785ad77bafcebee445
    www.comdirect.de sha1$0d9626705b9984b19bca19f8ceb18885b103d0e9
    meine.deutsche-bank.de sha1$ba54c47dd5493db54cd0f76a120cac11cdfb76f8
    www.twitter.com sha1$256e402523c3418e1e9a0185448458af96c4a1be
    www.facebook.com sha1$13d0376c2ab2143640a62d08bb71f5e9ef571361
    www.live.com sha1$10c56ee9e2acaf2e77caeb7072bf6522dd7422b8
);

my $proxy = ( $ENV{https_proxy} || $ENV{http_proxy} || '' )
    =~m{^(?:\w+://)?([\w\-.:\[\]]+:\d+)/?$} && $1;

my @cap = ('SSL_verifycn_name');
push @cap, 'SSL_hostname' if IO::Socket::SSL->can_client_sni();
plan tests => 1 + (1+@cap)*keys(%hosts);

my $builtin_ca_ok = 0;
my $builtin_ca_fail = 0;
while ( my ($host,$fp) = each %hosts ) {
    SKIP: {
	# first check if we can connect at all
	my @cl;
	for my $cap ('fp','nocn',@cap,'noca') {
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
		
	    skip "cannot connect to $host:443 with $ipclass: $!",1+@cap 
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

	# check if it can verify against builtin CA store
	$cl = shift(@cl);
	if ( ! IO::Socket::SSL->start_SSL($cl)) {
	    $builtin_ca_fail++;
	    skip "ssl upgrade failed with builtin CA store",1+@cap;
	}
	diag("check $host against builtin CA store ok");
	$builtin_ca_ok++;

	for my $cap (@cap) {
	    my $cl = shift(@cl);
	    # try to upgrade with SSL using default CA path
	    if ( IO::Socket::SSL->start_SSL($cl,
		SSL_verify_mode => 1,
		SSL_verifycn_scheme => 'http',
		$cap => $host,
	    )) {
		pass("SSL upgrade $host with default CA and $cap");
	    } elsif ( $SSL_ERROR =~m{verify failed} ) {
		fail("SSL upgrade $host with default CA and $cap: $SSL_ERROR");
	    } else {
		pass("SSL upgrade $host with no CA failed but not because of verify problem: $SSL_ERROR");
	    }
	}

	# it should fail when we use no default ca, even on OS X
	# https://hynek.me/articles/apple-openssl-verification-surprises/
	$cl = shift(@cl);
	if ( IO::Socket::SSL->start_SSL($cl, SSL_ca_file => \'' )) {
	    fail("SSL upgrade $host with no CA succeeded");
	} elsif ( $SSL_ERROR =~m{verify failed} ) {
	    pass("SSL upgrade $host with no CA failed");
	} else {
	    pass("SSL upgrade $host with no CA failed but not because of verify problem: $SSL_ERROR");
	}
    }
}

if ( $builtin_ca_ok + $builtin_ca_fail == 0 ) {
    pass("no successful connects, not checking CA usage");
} else {
    ok( $builtin_ca_ok,
	"verification against builtin CA store:  $builtin_ca_ok/".(0+keys %hosts));
}
