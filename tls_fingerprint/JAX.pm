# Copyright Steffen Ullrich 2023
# License: public domain (no restrictions)

package JAX;
use strict;
use warnings;
use Digest::MD5 'md5_hex';
use Digest::SHA 'sha256_hex';

use Exporter 'import';
our @EXPORT = qw(ja3 ja4 ja3s);

my %grease = map { $_ =>1 } (
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
);

sub ja3s {
    my ($buf,$raw,$ordered) = @_;

    #  2 byte: protocol version
    # 32 byte: random
    # 1/...  : session id
    #  2 byte: cipher suite
    #  1 byte: compression method
    # 2/...  : extensions
    my ($ver, $cipher, $ext) = unpack("n x32 c/x n x n/a", $buf);

    my @ext;
    while (length($ext)>2) {
	# 2 byte: extension type
	# 2|... : extension data
	(my $ext_type, $ext) = unpack("n n/x a*", $ext);
	push @ext, $ext_type if ! $grease{$ext_type};
    }
    my $fp = join(",",
	$ver,
	$cipher,
	join("-", $ordered ? sort(@ext) : @ext)
    );
    return $raw ? $fp : md5_hex($fp);
}

sub ja3 {
    my ($buf,$raw,$ordered) = @_;

    #  2 byte: protocol version
    # 32 byte: random
    # 1/..   : session id
    # 2/...  : cipher suites
    # 1/...  : compression methods
    # 2/...  : extensions
    my ($ver, $ciphers, $ext) = unpack("n x32 c/x n/a c/x n/a", $buf);

    my @ciphers = grep { !$grease{$_} } unpack("n*", $ciphers);

    my (@ext, @elliptic_curve, @elliptic_curve_point_format);
    while (length($ext)>2) {
	# 2 byte: extension value
	# 2|... : extension data
	(my $ext_val, my $ext_data, $ext) = unpack("n n/a a*", $ext);
	next if $grease{$ext_val};
	push @ext, $ext_val;
	if ($ext_val == 0x0a) {
	    # Elliptic curve points
	    @elliptic_curve = unpack("x2 n*", $ext_data);
	} elsif ($ext_val == 0x0b) {
	    # Elliptic curve point formats
	    @elliptic_curve_point_format = unpack("x c*", $ext_data);
	}
    }

    my $fp = join(",",
	$ver,
	join("-", @ciphers),
	join("-", $ordered ? sort(@ext) : @ext),
	join("-", @elliptic_curve),
	join("-", @elliptic_curve_point_format),
    );
    return $raw ? $fp : md5_hex($fp);
}

sub ja4 {
    my ($buf,$raw,$ordered) = @_;
    $ordered //= 1; # default ordered

    #  2 byte: protocol version
    # 32 byte: random
    # 1/..   : session id
    # 2/...  : cipher suites
    # 1/...  : compression methods
    # 2/...  : extensions
    my ($ver, $ciphers, $ext) = unpack("n x32 c/x n/a c/x n/a", $buf);

    my @ciphers = grep { !$grease{$_} } unpack("n*", $ciphers);
    my $sni = 'i';
    my $alpn = '00';

    my (@ext,@sigalg);
    my $lenext = 0;
    while (length($ext)>2) {
	# 2 byte: extension value
	# 2|... : extension data
	(my $ext_val, my $ext_data, $ext) = unpack("n n/a a*", $ext);
	next if $grease{$ext_val};
	$lenext++;
	push @ext, $ext_val;
	if ($ext_val == 43) {
	    # supported_versions
	    my @v = grep { !$grease{$_} } unpack("x n*", $ext_data);
	    $ver = $v[0] if @v;
	} elsif ($ext_val == 13) {
	    # signature_algorithm
	    @sigalg = grep { !$grease{$_} } unpack("x2 n*", $ext_data);
	} elsif ($ext_val == 0) {
	    # server_name
	    pop @ext; # don't include in extension list
	    $sni = 'd';
	} elsif ($ext_val == 16) {
	    # alpn
	    pop @ext; # don't include in extension list
	    eval { $alpn = unpack("x2 c/a", $ext_data); };
	    $alpn = substr($alpn,0,1).substr($alpn,-1,1);
	}
    }
    $ver = $ver>0x0300 ? $ver - 0x0300 + 9 : # 0x303 -> TLS 1.2
	$ver == 0x0300 ? 's3' :
	$ver == 512 ? 's2' :
	$ver == 256 ? 's1' :
	'00';

    for (\@ciphers, \@ext, \@sigalg) {
	$_ = sprintf("%04x", $_ ) for @$_;

    }
    my $hash = $raw ? sub { shift } : sub { substr(sha256_hex(shift),0,12) };
    return sprintf("%s%02d%s%02d%02d%s_%s_%s",
	't',
	$ver,
	$sni,
	~~@ciphers,
	$lenext,
	$alpn,
	$hash->(join(",", $ordered? sort(@ciphers) : @ciphers)),
	$hash->( join(",", $ordered ? sort(@ext) : @ext) .
	    (@sigalg ? "_".join(",", @sigalg) : "")),
    );
}

1;
