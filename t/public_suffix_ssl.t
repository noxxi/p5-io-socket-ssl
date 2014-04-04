use strict;
use warnings;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;
use Test::More;

if ( grep { $^O =~m{$_} } qw( MacOS VOS vmesa riscos amigaos ) ) {
    plan skip_all => "fork not implemented on this platform";
}

my @tests = qw(
    fail:www.com
    ok:www.bar.com
    ok:www.foo.bar.com
    ok:www.foo.co.uk
    fail:www.co.uk
    ok:www.foo.bl.uk
    ok:www.bl.uk
    fail:bar.kobe.jp
    fail:www.bar.kobe.jp
    ok:www.foo.bar.kobe.jp
    fail:city.kobe.jp
    ok:www.city.kobe.jp
    fail:foo.nodomain
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
	# client initially send line with expected CN
	chop( my $cn = <$cl> ) or last;
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
alarm(30);

close($server);
for my $test (@tests) {
    my ($expect,$host) = $test=~m{^(ok|fail):(\S+)} or die $test;
    ( my $cn = $host ) =~s{[^.]+}{*}; # expect cn to have wildcard
    my $cl = IO::Socket::INET->new($saddr) or die "failed to connect: $!";
    print $cl "$cn\n";
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


