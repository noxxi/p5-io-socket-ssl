use strict;
use warnings;
use Test::More;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;

my $ipclass = 'IO::Socket::INET';
for( qw( IO::Socket::IP IO::Socket::INET6  )) {
    eval { require $_ } or next;
    $ipclass = $_;
    last;
}

# host:port fingerprint_cert subject_hash_ca
my @tests = qw(
    www.google.com:443 sha1$93125bb97d02aa4536b4ec9a7ca01ad8927314db 578d5c04
    www.yahoo.com:443 sha1$71167492535fbdaa3ab6fec242ce183930d27603 415660c1
    www.comdirect.de:443 sha1$ca16159c49de301ab1ae69ef1d3c0205f54ebaaa 415660c1
    meine.deutsche-bank.de:443 sha1$1331596b6ecfe54f2018b6d16046c7046dc84048 415660c1
    www.twitter.com:443 sha1$add53f6680fe66e383cbac3e60922e3b4c412bed b204d74a
    www.facebook.com:443 sha1$45bfee628eec0ba06dfb860c865ffdb71502a541 244b5494
    www.live.com:443 sha1$69e85345bfa05c1beb1352dad0b8c61abe42f26c b204d74a
);


my %ca = IO::Socket::SSL::default_ca();
plan skip_all => "no default CA store found" if ! %ca;

my %have_ca;
# some systems seems to have junk in the CA stores
# so better wrap it into eval
eval {
    for my $f (
	( $ca{SSL_ca_file} ? ($ca{SSL_ca_file}) : ()),
	( $ca{SSL_ca_path} ? glob("$ca{SSL_ca_path}/*") :()),
	) {
	open( my $fh,'<',$f ) or next;
	my $pem;
	while (<$fh>) {
	    if ( m{^--+END} ) {
		my $cert = PEM_string2cert($pem.$_);
		$pem = undef;
		$cert or next;
		my $hash = Net::SSLeay::X509_subject_name_hash($cert);
		$have_ca{sprintf("%08x",$hash)} = 1;
	    } elsif ( m{^--+BEGIN (TRUSTED |X509 |)CERTIFICATE-+} ) {
		$pem = $_;
	    } elsif ( $pem ) {
		$pem .= $_;
	    }
	}
    }
};
diag( "found ".(0+keys %have_ca)." CA certs");
plan skip_all => "no CA certs found" if ! %have_ca;

my $proxy = ( $ENV{https_proxy} || $ENV{http_proxy} || '' )
    =~m{^(?:\w+://)?([\w\-.:\[\]]+:\d+)/?$} && $1;

my @cap = ('SSL_verifycn_name');
push @cap, 'SSL_hostname' if IO::Socket::SSL->can_client_sni();
plan tests => (1+@cap)*(@tests/3);

while ( @tests ) {
    my ($host,$fp,$ca_hash) = splice(@tests,0,3);
    my $port = $host =~s{:(\d+)$}{} && $1;
    SKIP: {

	# first check if we have the CA in store
	skip "no root CA $ca_hash for $host in store",1+@cap
	    if ! $have_ca{$ca_hash};
	diag("have root CA for $host in store");

	# then build inet connections for later SSL upgrades
	my @cl;
	for my $cap ('fp','nocn',@cap,'noca') {
	    my $cl;
	    if ( ! $proxy ) {
		# direct connection
		$cl = $ipclass->new(
		    PeerAddr => $host,
		    PeerPort => $port,
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
	    skip "ssl upgrade failed with builtin CA store",1+@cap;
	}
	diag("check $host against builtin CA store ok");

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
