use strict;
use warnings;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;
use Test::More;

if ( grep { $^O =~m{$_} } qw( MacOS VOS vmesa riscos amigaos ) ) {
    plan skip_all => "fork not implemented on this platform";
}

my @tests = qw(
    fail:com
    fail:googleapis.com
    ok:ajax.googleapis.com
    ok:google.com
    ok:www.bar.com
    ok:www.foo.bar.com
    ok:www.foo.co.uk
    fail:co.uk
    ok:bl.uk
    ok:www.bl.uk
    fail:bar.kobe.jp
    ok:foo.bar.kobe.jp
    ok:www.foo.bar.kobe.jp
    ok:city.kobe.jp
    ok:www.city.kobe.jp
    fail:nodomain
    ok:foo.nodomain
    ok:www.foo.nodomain
);

$|=1;
plan tests => 0+@tests;

# create listener
my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen => 2,
) || die "not ok #tcp listen failed: $!\n";
my $saddr = $server->sockhost.':'.$server->sockport;
#diag("listen at $saddr");

# create CA - certificates will be created on demand
my ($cacert,$cakey) = CERT_create( CA => 1 );

defined( my $pid = fork() ) || die $!;
if ( ! $pid ) {
    while (@tests) {
	my $cl = $server->accept or next;
	shift(@tests); # only for counting
	# client initially sends line with expected CN
	defined( my $cn = <$cl> ) or do {
	    warn "failed to get expected name from client, remaining ".(0+@tests);
	    next;
	};
	chop($cn);
	print $cl "ok\n";
	my ($cert,$key) = CERT_create( 
	    subject => { CN => $cn },
	    issuer  => [ $cacert,$cakey ],
	    key     => $cakey, # reuse to speed up
	);
	#diag("created cert for $cn");
	<$cl> if IO::Socket::SSL->start_SSL($cl,
	    SSL_server => 1,
	    SSL_cert   => $cert,
	    SSL_key    => $key,
	);
    }
    exit(0);
}

# if anything blocks - this will at least finish the test
alarm(60);
$SIG{ALRM} = sub { die "test takes too long" };

close($server);
for my $test (@tests) {
    my ($expect,$host) = $test=~m{^(ok|fail):(\S+)} or die $test;
    ( my $cn = $host ) =~s{[^.]+}{*}; # expect cn to have wildcard
    my $cl = IO::Socket::INET->new($saddr) or die "failed to connect: $!";
    print $cl "$cn\n";
    <$cl>;
    my $sslok = IO::Socket::SSL->start_SSL($cl,
	SSL_verifycn_name => $host,
	SSL_verifycn_scheme => 'http',
	SSL_ca => [$cacert],
    );
    if ( ! $sslok ) {
	is( $sslok?1:0, $expect eq 'ok' ? 1:0, "ssl $host against $cn -> $expect ($SSL_ERROR)");
    } else {
	is( $sslok?1:0, $expect eq 'ok' ? 1:0, "ssl $host against $cn -> $expect");
    }
}


