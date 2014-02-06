use strict;
use warnings;
use Test::More;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;

plan tests => 6;
plan skip_all => "fork not implemented on this platform"
    if $^O =~m{MacOS|VOS|vmesa|riscos|amigaos};

my ($cert1,$key1) = CERT_create( subject => { CN => 'cert1' });
my ($cert2,$key2) = CERT_create( subject => { CN => 'cert2' });

my ($saddr1,$fp1) = _server($cert1,$key1);
my ($saddr2,$fp2) = _server($cert2,$key2);

for my $test (
    [ $saddr1, $fp1, "accept fp1 for saddr1", 1 ],
    [ $saddr2, $fp2, "accept fp2 for saddr2", 1 ],
    [ $saddr1, $fp2, "reject fp2 for saddr1", 0 ],
    [ $saddr2, $fp1, "reject fp1 for saddr2", 0 ],
    [ $saddr1, [$fp1,$fp2], "accept fp1|fp2 for saddr1", 1 ],
    [ $saddr2, [$fp1,$fp2], "accept fp1|fp2 for saddr2", 1 ],
) {
    my ($saddr,$fp,$what,$expect) = @$test;
    my $cl = IO::Socket::INET->new( $saddr ) or die $!;
    my $ok = IO::Socket::SSL->start_SSL($cl,
	SSL_verify_mode => 1,
	SSL_fingerprint => $fp
    );
    ok( ($ok?1:0) == ($expect?1:0),$what);
}


my @child;
END { kill 9,@child }
sub _server {
    my ($cert,$key) = @_;
    my $sock = IO::Socket::INET->new( LocalAddr => '0.0.0.0', Listen => 10 )
	or die $!;
    defined( my $pid = fork()) or die $!;
    if ( $pid ) {
	push @child,$pid;
	return (
	    '127.0.0.1:'.$sock->sockport,
	    'sha1$'.unpack('H*',Net::SSLeay::X509_get_fingerprint($cert,'sha1'))
	);
    }

    while (1) {
	my $cl = $sock->accept or next;
	IO::Socket::SSL->start_SSL($cl,
	    SSL_server => 1,
	    SSL_cert  => $cert,
	    SSL_key   => $key
	);
    }
}
