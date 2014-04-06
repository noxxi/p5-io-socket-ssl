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
    www.yahoo.com sha1$37363a34413a31393a45313a45423a32363a39313a37453a46323a39383a43463a37383a35413a44373a37423a41463a43453a42453a45343a3435
    meine.deutsche-bank.de sha1$42413a35343a43343a37443a44353a34393a33443a42353a34433a44303a46373a36413a31323a30433a41433a31313a43443a46423a37363a4638
    www.twitter.com sha1$32353a36453a34303a32353a32333a43333a34313a38453a31453a39413a30313a38353a34343a38343a35383a41463a39363a43343a41313a4245
    www.facebook.com sha1$31333a44303a33373a36433a32413a42323a31343a33363a34303a41363a32443a30383a42423a37313a46353a45393a45463a35373a31333a3631
);

my $proxy = ( $ENV{https_proxy} || $ENV{http_proxy} || '' )
    =~m{^(?:\w+://)?([\w\-.:\[\]]+:\d+)/?$} && $1;

my @cap = ('SSL_verifycn_name');
push @cap, 'SSL_hostname' if IO::Socket::SSL->can_client_sni();
plan tests => 1 + (1+@cap)*keys(%hosts);

my $builtin_ca_ok = 0;
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
	skip "ssl upgrade failed with builtin CA store",1+@cap
	    if ! IO::Socket::SSL->start_SSL($cl);
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

ok( $builtin_ca_ok,
    "verification against builtin CA store:  $builtin_ca_ok/".(0+keys %hosts));
