use strict;
use warnings;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;
use IO::Select;
use Socket 'MSG_PEEK';

use Getopt::Long qw(:config posix_default bundling);

my $DEBUG;
{
    my $addr = '0.0.0.0:8080';
    my $ciphers;
    my $version;
    my $deny_tls12 = my $deny_tls11 = 0;
    my $issuer;
    my $wildcards = 0;
    GetOptions(
        'h|help'      => sub { usage() },
        'd|debug'     => \$DEBUG,
        'C|ciphers=s' => \$ciphers,
        'V|version=s' => \$version,
        'deny-tls12'  => \$deny_tls12,
        'deny-tls11'  => \$deny_tls11,
	'wildcards=i' => \$wildcards,
	'issuer=s'    => \$issuer,
    );

    sub usage {
        print STDERR <<USAGE;

Usage: $0 [options] [listen-ip:port]
Simulates Proxy, listens on listen-ip:port (default $addr).
Will automatically distinguish between normal HTTP requests, proxy requests 
and direct SSL connects
Options:
  -h|--help      - this usage
  -d|--debug     - some debugging messages
  -C|--ciphers C - specify the ciphers to use instead of builtin
  -V|--version V - specify SSL version to use instead of builtin
  --issuer F     - use CA in file F (containing certificate and key in PEM) as 
                   issuer instead of builtin
  --deny-tls12   - close connection on TLSv12 handshakes from client
  --deny-tls11   - close connection on TLSv11 handshakes from client
  --wildcards N  - generate certificate with N left wildcards (default 0)
USAGE
	exit(1);
    }

    $addr = shift if @ARGV;
    usage() if @ARGV;

    my $data = $issuer ? do {
	open( my $fh,'<',$issuer ) or die "open $issuer: $!";
	local $/; <$fh> 
    } : do { 
	local $/; <DATA> 
    };
    my $issuer_cert = PEM_string2cert($data) or die "no issuer cert found";
    my $issuer_key  = PEM_string2key($data) or die "no issuer key found";

    proxy_server( $addr, 
	deny_tls12 => $deny_tls12,
	deny_tls11 => $deny_tls11,
	$ciphers ? ( SSL_cipher_list => $ciphers ):(),
	$version ? ( SSL_version => $version ):(),
	issuer_cert => $issuer_cert,
	issuer_key  => $issuer_key,
	wildcards   => $wildcards,
    );
}



# ----------------------------------------------------------------------------
# simulate Proxy
# ----------------------------------------------------------------------------
sub proxy_server {
    my ($addr,%args) = @_;
    my %sslargs;
    $sslargs{$_} = delete $args{$_} for grep { m{^SSL_} } keys %args;

    # dynamically create server certs
    my $wildcards   = delete $args{wildcards} || 0;
    my $issuer_cert = delete $args{issuer_cert};
    my $issuer_key  = delete $args{issuer_key};
    my $get_cert = do {
	my %cache;
	sub {
	    my $host = my $cn = shift;
	    $cn =~s{(^|\.)([\w\-]+)}{$1*} for(1..$wildcards);
	    if ( $cache{$cn} ) {
		debug("reusing cert for $cn ($host) wildcards=$wildcards");
	    } else {
		debug("creating cert for $cn ($host) wildcards=$wildcards");
		$cache{$cn} = [ CERT_create(
		    subject => { commonName => $cn },
		    issuer_cert => $issuer_cert,
		    issuer_key => $issuer_key,
		)];
	    }
	    return @{ $cache{$cn} };
	}
    };

    debug("listen on $addr");
    my $srv = IO::Socket::INET->new(
	LocalAddr => $addr,
	Listen => 1,
	Reuse => 1
    ) or die $!;

    my $cl;
    while (1) {
	ACCEPT:
	$cl = undef;
	debug("waiting for request...");
	$cl = $srv->accept or next;

	# peek into socket to determine if this is SSL or not
	# minimal request is "GET / HTTP/1.1\n\n"
	my $buf = '';
	_peek($cl,\$buf,15) or do {
	    debug("failed to get data from client");
	    goto ACCEPT;
	};

	my $ssl_host = undef;
	if ( $buf =~m{\A[A-Z]{3,} } ) {
	    # looks like HTTP
	    $buf = '';
	} else {
	    # does not look like HTTP, assume direct SSL
	    $ssl_host = "direct.ssl.access";
	}

	SSL_UPGRADE:
	my $got_ciphers = '';
	if ( $ssl_host ) {

	    if ( $args{deny_tls12} || $args{deny_tls11} ) {
		_peek($cl,\$buf,11) or do {
		    debug("failed to get client hello");
		    goto ACCEPT;
		};
		if ( $args{deny_tls12} && $buf =~m{^.{9}\x03\x03}s ) {
		    debug("got TLSv1.2 handshake - cut!");
		    goto ACCEPT;
		} elsif ( $args{deny_tls11} && $buf =~m{^.{9}\x03\x02}s ) {
		    debug("got TLSv1.1 handshake - cut!");
		    goto ACCEPT;
		}
	    }

	    my ($cert,$key) = $get_cert->($ssl_host);
	    debug("upgrade to SSL with certificate for $ssl_host");
	    IO::Socket::SSL->start_SSL( $cl,
		SSL_server => 1,
		SSL_cert => $cert,
		SSL_key  => $key,
		%sslargs,
	    ) or do {
		debug("SSL handshake failed: $SSL_ERROR");
		goto ACCEPT;
	    };
	    $got_ciphers = $cl->get_cipher;
	}

	REQUEST:
	# read header
	my $req = '';
	while (<$cl>) {
	    $_ eq "\r\n" and last;
	    $req .= $_;
	}
	if ( $req =~m{\ACONNECT ([^\s:]+)} ) {
	    if ( $ssl_host ) {
		debug("CONNECT inside SSL tunnel - cut");
		next ACCEPT;
	    }
	    $ssl_host = $1;

	    # simulate proxy
	    print $cl "HTTP/1.0 200 ok\r\n\r\n";
	    debug("got proxy request to establish tunnel: CONNECT $ssl_host");
	    goto SSL_UPGRADE;
	}

	my ($met,$ver,$hdr) = $req 
	    =~m{\A([A-Z]+) \S+ HTTP/(1\.[01])\r?\n(.*)\Z}s or do {
	    debug("bad request $req");
	    goto ACCEPT;
	};
	$hdr =~s{\r?\n([ \t])}{$1}g; # continuation lines

	my $rqbody = '';
	my $rqchunked;
	if ( $ver eq '1.1' and $hdr =~m{^Transfer-Encoding: *chunked}mi ) {
	    $rqchunked = 1;
	    debug("chunked request body");
	    while (1) {
		my $h = <$cl>;
		my $len = $h =~m{\A([\da-fA-F]+)\s*(?:;.*)?\r?\n\Z} && hex($1) // do {
		    debug("bad chunking header in request body");
		    goto ACCEPT
		};
		if ($len) {
		    my $n = read($cl,$rqbody,$len,length($rqbody));
		    if ( $n != $len ) {
			debug("eof inside chunk in request body");
			goto ACCEPT;
		    }
		}
		$h = <$cl>; 
		$h =~m{\A\r?\n\Z} or do {
		    debug("expected newline after chunk, got '$h'");
		    goto ACCEPT;
		};
		last if ! $len;
	    }
	} elsif ( my $len = $hdr=~m{^Content-length: *(\d+)}mi && $1 ) {
	    debug("request body with content-length=$len");
	    my $n = read($cl,$rqbody,$len);
	    if ( $n != $len ) {
		debug("eof while reading request body, got $n of $len bytes");
		goto ACCEPT;
	    }
	}

	my $body = 
	    ( $ssl_host ? "SSL_HOST: $ssl_host\nCIPHERS: $got_ciphers\n": "NO SSL\n" )
	    . "---------\n"
	    . $req;
	if ( $rqchunked ) {
	    $body .= "--------- (chunked) body size=".(length($rqbody))."------\n$rqbody\n";
	} elsif ( $rqbody ne '' ) {
	    $body .= "--------- body size=".(length($rqbody))." ------\n$rqbody\n";
	}

	print $cl "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n".
	    "Content-length: ".length($body)."\r\n".
	    "\r\n".
	    $body;
    }
}


sub debug {
    $DEBUG or return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    print STDERR "DEBUG: $msg\n";
}

sub _peek {
    my ($cl,$rbuf,$len) = @_;
    while (length($$rbuf)<$len) { 
	my $lbuf;
	if ( ! IO::Select->new($cl)->can_read(30)
	    or ! defined recv($cl,$lbuf,20,MSG_PEEK)) {
	    return;
	}
	$$rbuf .= $lbuf;
    }
    return 1;
}

# ----------------------------------------------------------------------------
# this was used to create CA cert
# ----------------------------------------------------------------------------
#| use IO::Socket::SSL::Utils;
#| my ($cacert,$key) = CERT_create( CA => 1,
#|     subject => { organizationName => 'genua mbh', commonName => 'Test CA' }
#| );
#| print PEM_cert2string($cacert).PEM_key2string($key);

__DATA__
-----BEGIN CERTIFICATE-----
MIICVjCCAb+gAwIBAgIFAIbQ7t4wDQYJKoZIhvcNAQEFBQAwJjEQMA4GA1UEAxMH
VGVzdCBDQTESMBAGA1UEChMJZ2VudWEgbWJoMB4XDTEzMTAyMzA4MjI0MFoXDTE0
MTAyMzA4MjI0MFowJjEQMA4GA1UEAxMHVGVzdCBDQTESMBAGA1UEChMJZ2VudWEg
bWJoMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBD9oBSf8pueg3BxNdf6Mm
PKGmh46R0O3xNOE/HfXc9Z2WxgLEX4PaYMwdzgFuPcVTZycI5NdhM53yydnTilsX
eFct5D2Bz3faiIOB2WnoiNft15YGCdyeue9kf2NkYRLs3eBQDPeU/cXKyfcHb1dS
QpQNKiyL/ono1c0kZRoP3wIDAQABo4GPMIGMMB0GA1UdDgQWBBReUpKjaiNSYfZT
X2+XsfQsYZef0zAfBgNVHSMEGDAWgBReUpKjaiNSYfZTX2+XsfQsYZef0zA8BgNV
HSMENTAzoSqkKDAmMRAwDgYDVQQDEwdUZXN0IENBMRIwEAYDVQQKEwlnZW51YSBt
YmiCBQCG0O7eMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAg9H/7umS
4bKSEyyCzzqyR1vf735wPnUmTL7NrduPCaT/bLVRPmDwhyRrpNVedICxyU3NK9fc
r0Fj12oBBbvLACm8Xfnt23x8IbnGXIz7n5aTFvrv2l3rVMkZOFqo/DFtFnfYGuY8
/N4DtEHG21dwpMrDxXE1pAE5IY+vRMlNEtA=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMEP2gFJ/ym56DcH
E11/oyY8oaaHjpHQ7fE04T8d9dz1nZbGAsRfg9pgzB3OAW49xVNnJwjk12EznfLJ
2dOKWxd4Vy3kPYHPd9qIg4HZaeiI1+3XlgYJ3J6572R/Y2RhEuzd4FAM95T9xcrJ
9wdvV1JClA0qLIv+iejVzSRlGg/fAgMBAAECgYBK8Hs/6tg3+yjPS1jR/zx2GCzr
Nk05/q6N5WfVlyybg1+TafMjBKxqtQ4mN5PIlgOldzHouuN7oIyb9IwwF9F5YeUb
8WTK1iLzTmrcfFJmtRyj0ITF5gb+r6PhPxGr4yt8f9bzaIj7G57a+QT9gXKnLKao
AN4Vxx51MAPvMeREYQJBAPstPjOyWxLsT8yBphlok2w4MnWQASsrflrL6MzuJYOq
zpVxQF3lwSHukhoUhDoyee9miY2kcB9H9PoXWbq4io8CQQDExOwxTlYnyqyvKjFq
vXchcNZ4wCU5sf6pzXF2l6Hb6eCuqYlarMu2JN0h7CC0Jq4qr1BalgesS3WUT1M8
dw2xAkB6Kfgd5rp7CqqJOemSZBWHxhFssnyPBZlwCcsRmSZv0qylbK60vKFhooo2
2xGwyIob0RBH7tmFrVbOKHtA4K6rAkA3sRi8t9RQvN91UHbeJDP0phA96vxeQQ+4
Faq4iyBHswFhziBPJrsdmX9xG3kCJDSFZktS6EXRsSXdTTpc0cFxAkEAo5GS9dAY
7WLAcqNDUorHhFOcZouCYX3LRssikmwc0/dvc9DjwqpNqF1BHT6ucX0pqdQI+fp1
VHJ5f4e/SUTV3g==
-----END PRIVATE KEY-----
;
