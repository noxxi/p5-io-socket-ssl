use strict;
use warnings;
use Socket;
use IO::Socket::SSL 1.984;
use IO::Socket::SSL::Utils;
use Getopt::Long qw(:config posix_default bundling);


my $can_ocsp = IO::Socket::SSL->can_ocsp;
my $ocsp_cache = $can_ocsp && IO::Socket::SSL::OCSP_Cache->new;

my %starttls = (
    ''  => [ 443,undef, 'http' ],
    'smtp' => [ 25, \&smtp_starttls, 'smtp' ],
    'http_proxy' => [ 443, \&http_connect,' http' ],
    'http_upgrade' => [ 80, \&http_upgrade,'http' ],
    'imap' => [ 143, \&imap_starttls,'imap' ],
    'pop'  => [ 110, \&pop_stls,'pop3' ],
    'ftp'  => [ 21, \&ftp_auth,'ftp' ],
    'postgresql'  => [ 5432, \&postgresql_init,'default' ],
);

my $verbose = 0;
my $timeout = 10;
my ($stls,$stls_arg);
my $capath;
my $all_ciphers;
my $show_chain;
my $dump_chain;
GetOptions(
    'h|help' => sub { usage() },
    'v|verbose:1' => \$verbose,
    'd|debug:1' => \$IO::Socket::SSL::DEBUG,
    'T|timeout=i' => \$timeout,
    'CApath=s' => \$capath,
    'show-chain' => \$show_chain,
    'dump-chain' => \$dump_chain,
    'all-ciphers' => \$all_ciphers,
    'starttls=s' => sub {
	($stls,$stls_arg) = $_[1] =~m{^(\w+)(?::(.*))?$};
	usage("invalid starttls $stls") if ! $starttls{$stls};
    },
);
@ARGV or usage("no hosts given");
my %default_ca =
    ! $capath ? () :
    -d $capath ? ( SSL_ca_path => $capath, SSL_ca_file => '' ) :
    -f $capath ? ( SSL_ca_file => $capath, SSL_ca_path => '' ) :
    die "no such file or dir: $capath";
die "need Net::SSLeay>=1.58 for showing chain" if $show_chain
    && ! defined &IO::Socket::SSL::peer_certificates;


sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Analyze SSL connectivity for problems.
Usage: $0 [options] (host|host:port)+
Options:
  -h|--help              - this screen
  -v|--verbose level     - verbose output
  -d|--debug level       - IO::Socket::SSL/Net::SSLeay debugging
  --CApath file|dir      - use given dir|file instead of system default CA store
  --all-ciphers          - find out all supported ciphers
  --show-chain           - show certificate chain
  --dump_chain           - dump certificate chain, e.g. all certificates as PEM
  --starttls proto[:arg] - start plain and upgrade to SSL with starttls protocol
			   (imap,smtp,http_upgrade,http_proxy,pop,ftp,postgresql)
  -T|--timeout T         - use timeout (default 10)

Examples:

  $0 --show-chain --all-ciphers -v3 www.live.com:443
  $0 --starttls http_proxy:proxy_host:proxy_port www.live.com:443
  $0 --starttls imap mail.gmx.de

USAGE
    exit(2);
}



my @tests;
for my $host (@ARGV) {
    my ($ip,$port);
    $host =~m{^(?:\[(.+)\]|([^:]+))(?::(\w+))?$} or die "invalid dst: $host";
    $host = $1||$2;
    my $st = $starttls{$stls ||''};
    $port = $3 || $st->[0] || 443;
    if ( $host =~m{:|^[\d\.]+$} ) {
	$ip = $host;
	$host = undef;
    }
    push @tests, [ $host||$ip,$port,$host,$st->[1],$st->[2] || 'default' ];
}

my $ioclass = IO::Socket::SSL->can_ipv6 || 'IO::Socket::INET';
for my $test (@tests) {
    my ($host,$port,$name,$stls_sub,$scheme) = @$test;
    VERBOSE(1,"checking host=$host port=$port".
	($stls ? " starttls=$stls":""));

    my $tcp_connect = sub {
	my $tries = shift || 1;
	my ($cl,$error);
	my %ioargs = (
	    PeerAddr => $host,
	    PeerPort => $port,
	    Timeout => $timeout,
	);
	for(1..$tries) {
	    if ($stls_sub) {
		last if $cl = eval { $stls_sub->(\%ioargs,$stls_arg) };
		$error = $@ || 'starttls error';
		$cl = undef;
	    } elsif ( $cl = $ioclass->new(%ioargs)) {
		last;
	    } else {
		$error = "tcp connect: $!";
	    }
	}
	$cl or die $error;
    };

    my @problems;

    # basic connects without verification or any TLS extensions (SNI, OCSP)
    # find out usable version and ciphers
    my ($use_version,$version,$cipher);
    BASE: for my $v (qw(
	SSLv23:!TLSv1_2:!TLSv1_1:!TLSv1
	SSLv23:!TLSv1_2:!TLSv1_1
	SSLv23:!TLSv1_2
	SSLv23
    )) {
	for my $ciphers ( '','HIGH:ALL' ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl,
		SSL_version => $v,
		SSL_verify_mode => 0,
		SSL_hostname => '',
		SSL_cipher_list => $ciphers,
	    )) {
		$use_version = $v;
		$version = $cl->get_sslversion();
		$cipher = $cl->get_cipher();
		VERBOSE(2,"version $v no verification, ciphers=$ciphers, no TLS extensions -> $version,$cipher");
	    } else {
		VERBOSE(2,"version $v, no verification, ciphers=$ciphers, no TLS extensions -> FAIL! $SSL_ERROR");
		if ( ! $ciphers && $v eq 'SSLv23' ) {
		    push @problems, "using default SSL_version $v, default ciphers -> $SSL_ERROR";
		} elsif ( ! $ciphers ) {
		    push @problems, "using SSL_version $v, default ciphers -> $SSL_ERROR";
		} else {
		    push @problems, "using SSL_version $v, ciphers $ciphers -> $SSL_ERROR";
		}
		last BASE if $version;
	    }
	}
    }
    if ($version) {
	VERBOSE(1,"successful connect with $version cipher=$cipher and no TLS extensions");
    } else {
	die "$host failed basic SSL connect: $SSL_ERROR\n";
    }

    my %conf = ( SSL_version => $version, SSL_cipher_list => $cipher );

    # check if host accepts SNI
    my $sni_status;
    if ( $name && $version !~m{^TLS} ) {
	VERBOSE(1,"disabling SNI because SSL version $version too low");
	$name = undef;
    }
    if ($name) {
	my $cl = &$tcp_connect;
	if ( IO::Socket::SSL->start_SSL($cl, %conf,
	    SSL_verify_mode => 0,
	    SSL_hostname => $name,
	)) {
	    VERBOSE(1,"SNI success");
	    $sni_status = 'ok';
	    $conf{SSL_hostname} = $name;
	} else {
	    VERBOSE(1,"SNI FAIL!");
	    $sni_status = "FAIL: $SSL_ERROR";
	    push @problems, "using SNI (default) -> $SSL_ERROR";
	    $name = undef;
	}
    }

    # get chain info
    my (@cert_chain,@cert_chain_nosni);
    if ($show_chain || $dump_chain) {
	for(
	    [ \%conf, \@cert_chain ],
	    ! $conf{SSL_hostname} ? () 
		: ([ { %conf, SSL_hostname => '' }, \@cert_chain_nosni ])
	) {
	    my ($conf,$chain) = @$_;
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl, %$conf,
		SSL_verify_mode => 0
	    )) {
		for my $cert ( $cl->peer_certificates ) {
		    my ($subject,$bits);
		    $subject = Net::SSLeay::X509_NAME_oneline(
			Net::SSLeay::X509_get_subject_name($cert));
		    if ( !@$chain) {
			my @san = $cl->peer_certificate('subjectAltNames');
			for( my $i=0;$i<@san;$i++) {
			    $san[$i] = 'DNS' if $san[$i] == 2;
			    $san[$i] .= ":".splice(@san,$i+1,1);
			}
			$subject .= " SAN=".join(",",@san) if @san;
		    }
		    if (my $pkey = Net::SSLeay::X509_get_pubkey($cert)) {
			$bits = eval { Net::SSLeay::EVP_PKEY_bits($pkey) };
			Net::SSLeay::EVP_PKEY_free($pkey);
		    }
		    push @$chain,[
			$bits||'???',
			$subject,
			join('|', grep { $_ } @{ CERT_asHash($cert)->{ocsp_uri} || []}),
			PEM_cert2string($cert),
		    ],
		}
	    } else {
		die "failed to connect with previously successful config: $SSL_ERROR";
	    }
	}
	# if same certificate ignore nosni
	if (@cert_chain_nosni 
	    && $cert_chain_nosni[0][3] eq $cert_chain[0][3]) {
	    VERBOSE(2,"same certificate in without SNI");
	    @cert_chain_nosni = ();
	}
    }

    # check verification against given/builtin CA w/o OCSP
    my $verify_status;
    my $cl = &$tcp_connect;
    if ( IO::Socket::SSL->start_SSL($cl, %conf,
	SSL_verify_mode => SSL_VERIFY_PEER,
	SSL_ocsp_mode => SSL_OCSP_NO_STAPLE,
	SSL_verifycn_scheme => 'none',
	%default_ca
    )) {
	%conf = ( %conf, SSL_verify_mode => SSL_VERIFY_PEER, %default_ca );
	if ( $cl->verify_hostname( $name,$scheme )) {
	    VERBOSE(1,"certificate verify success");
	    $verify_status = 'ok';
	    %conf = ( %conf,
		SSL_verifycn_scheme => $scheme,
		SSL_verifycn_name => $name,
	    );
	} else {
	    my @san = $cl->peer_certificate('subjectAltNames');
	    for( my $i=0;$i<@san;$i++) {
		$san[$i] = 'DNS' if $san[$i] == 2;
		$san[$i] .= ":".splice(@san,$i+1,1);
	    }
	    VERBOSE(1,"certificate verify - name does not match:".
		" subject=".$cl->peer_certificate('subject').
		" SAN=".join(",",@san)
	    );
	    $verify_status = 'name-mismatch';
	    %conf = ( %conf, SSL_verifycn_scheme => 'none');
	}

    } else {
	VERBOSE(1,"certificate verify FAIL!");
	$verify_status = "FAIL: $SSL_ERROR";
	push @problems, "using certificate verification (default) -> $SSL_ERROR";
    }

    # check with OCSP stapling
    my $ocsp_staple;
    if ( $can_ocsp && $verify_status eq 'ok' ) {
	my $cl = &$tcp_connect;
	$conf{SSL_ocsp_cache} = $ocsp_cache;
	if ( IO::Socket::SSL->start_SSL($cl, %conf)) {
	    if ( ${*$cl}{_SSL_ocsp_verify} ) {
		$ocsp_staple = 'got stapled response',
	    } else {
		$ocsp_staple = 'no stapled response',
	    }
	    VERBOSE(1,"OCSP stapling: $ocsp_staple");
	} else {
	    $ocsp_staple = "FAIL: $SSL_ERROR";
	    $conf{SSL_ocsp_mode} = SSL_OCSP_NO_STAPLE;
	    VERBOSE(1,"access with OCSP stapling FAIL!");
	    push @problems, "using OCSP stapling (default) -> $SSL_ERROR";
	}
    }

    my $ocsp_status;
    if ( $can_ocsp && $verify_status eq 'ok' ) {
	my $cl = &$tcp_connect;
	$conf{SSL_ocsp_mode} |= SSL_OCSP_FULL_CHAIN;
	if ( ! IO::Socket::SSL->start_SSL($cl, %conf)) {
	    die sprintf("failed with SSL_ocsp_mode=%b, even though it succeeded with default mode",
		$conf{SSL_ocsp_mode});
	}
	my $ocsp_resolver = $cl->ocsp_resolver;
	my %todo = $ocsp_resolver->requests;
	while (my ($uri,$req) = each %todo) {
	    VERBOSE(3,"need to send %d bytes OCSP request to %s",length($req),$uri);
	}
	my $errors = $ocsp_resolver->resolve_blocking();
	die "resolver not finished " if ! defined $errors;
	if ( ! $errors ) {
	    VERBOSE(1,"all certificates verified");
	    $ocsp_status = "good";
	} else {
	    VERBOSE(1,"failed to verify certicates: $errors");
	    $ocsp_status = "FAIL: $errors";
	}
	if (my $soft_error = $ocsp_resolver->soft_error) {
	    $ocsp_status .= " (soft error: $soft_error)"
	}
    }

    # check out all supported ciphers
    my @ciphers;
    {
	my $c = 'HIGH:ALL:eNULL';
	while ($all_ciphers || @ciphers<2 ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl, %conf,
		SSL_verify_mode => 0,
		SSL_ocsp_mode => 0,
		SSL_cipher_list => $c,
	    )) {
		push @ciphers, [ $cl->get_sslversion, $cl->get_cipher ];
		$c .= ":!".$ciphers[-1][1];
		VERBOSE(2,"connect with version %s cipher %s",
		    @{$ciphers[-1]});
	    } else {
		VERBOSE(3,"handshake failed with $c: $SSL_ERROR");
		last;
	    }
	}
    }

    # try to detect if the server accepts our cipher order by trying two
    # ciphers in different order
    my $server_cipher_order;
    if (@ciphers>=2) {
	my %used_cipher;
	for( "$ciphers[0][1]:$ciphers[1][1]","$ciphers[1][1]:$ciphers[0][1]" ) {
	    my $cl = &$tcp_connect;
	    if ( IO::Socket::SSL->start_SSL($cl,
		SSL_version => $use_version,
		SSL_verify_mode => 0,
		SSL_hostname => '',
		SSL_cipher_list => $_,
	    )) {
		$used_cipher{$cl->get_cipher}++;
	    } else {
		warn "failed to SSL handshake with SSL_cipher_list=$_: $SSL_ERROR";
	    }
	}
	if (keys(%used_cipher) == 2) {
	    VERBOSE(2,"client decides cipher order");
	    $server_cipher_order = 0;
	} elsif ( (values(%used_cipher))[0] == 2 ) {
	    VERBOSE(2,"server decides cipher order");
	    $server_cipher_order = 1;
	}
    }


    # summary
    print "-- $host port $port".($stls? " starttls $stls":"")."\n";
    print " ! $_\n" for(@problems);
    print " * maximum SSL version  : $version ($use_version)\n";
    print " * preferred cipher     : $cipher\n";
    print " * cipher order by      : ".(
	! defined $server_cipher_order ? "unknown\n" :
	$server_cipher_order ? "server\n" : "client\n"
    );
    print " * SNI supported        : $sni_status\n" if $sni_status;
    print " * certificate verified : $verify_status\n";
    if ($show_chain) {
	for(my $i=0;$i<@cert_chain;$i++) {
	    my $c = $cert_chain[$i];
	    print "   * [$i] bits=$c->[0], ocsp_uri=$c->[2], $c->[1]\n"
	}
	if (@cert_chain_nosni) {
	    print " * chain without SNI\n";
	    for(my $i=0;$i<@cert_chain_nosni;$i++) {
		my $c = $cert_chain_nosni[$i];
		print "   * [$i] bits=$c->[0], ocsp_uri=$c->[2], $c->[1]\n"
	    }
	}
    }
    print " * OCSP stapling        : $ocsp_staple\n" if $ocsp_staple;
    print " * OCSP status          : $ocsp_status\n" if $ocsp_status;
    if ($all_ciphers) {
	print " * supported ciphers\n";
	for(@ciphers) {
	    printf "   * %6s %s\n",@$_;
	}
    }
    if ($dump_chain) {
	print "---------------------------------------------------------------\n";
	for(my $i=0;$i<@cert_chain;$i++) {
	    my $c = $cert_chain[$i];
	    print "# $c->[1]\n$c->[3]\n";
	}
    }
}



sub smtp_starttls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server denies access: $line\n";
    print $cl "EHLO example.com\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept EHLO: $line\n";
    print $cl "STARTTLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    $code == 2 or die "server did not accept STARTTLS: $line\n";
    VERBOSE(3,"...reply to starttls: $line");
    return $cl;
}

sub imap_starttls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    <$cl>; # welcome
    print $cl "abc STARTTLS\r\n";
    while (<$cl>) {
	m{^abc (OK)?} or next;
	$1 or die "STARTTLS failed: $_";
	s{\r?\n$}{};
	VERBOSE(3,"...starttls: $_");
	return $cl;
    }
    die "starttls failed";
}

sub pop_stls {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    <$cl>; # welcome
    print $cl "STLS\r\n";
    my $reply = <$cl>;
    die "STLS failed: $reply" if $reply !~m{^\+OK};
    $reply =~s{\r?\n}{};
    VERBOSE(3,"...stls $reply");
    return $cl;
}

sub http_connect {
    my ($ioargs,$proxy) = @_;
    $proxy or die "no proxy host:port given";
    $proxy =~m{^(?:\[(.+)\]|([^:]+)):(\w+)$} or die "invalid dst: $proxy";
    my $cl = $ioclass->new( %$ioargs,
	PeerAddr => $1||$2,
	PeerPort => $3,
    ) or die "tcp connect: $!";
    print $cl "CONNECT $ioargs->{PeerAddr}:$ioargs->{PeerPort} HTTP/1.0\r\n\r\n";
    my $hdr = _readlines($cl,qr/\r?\n/);
    $hdr =~m{\A(HTTP/1\.[01]\s+(\d\d\d)[^\r\n]*)};
    die "CONNECT failed: $1" if $2 != 200;
    VERBOSE(3,"...connect request: $1");
    return $cl;
}

sub http_upgrade {
    my ($ioargs,$arg) = @_;
    my $hostname = $ioargs->{PeerAddr};
    my $cl = $ioclass->new(%$ioargs) or die "tcp connect: $!";
    my $rq;
    if ( $arg && $arg =~m{^get(?:=(\S+))?}i ) {
	my $path = $1 || '/';
	$rq = "GET $path HTTP/1.1\r\n".
	    "Host: $hostname\r\n".
	    "Upgrade: TLS/1.0\r\n".
	    "Connection: Upgrade\r\n".
	    "\r\n";
    } else {
	my $path = $arg && $arg =~m{^options=(\S+)}i
	    ? $1:'*';
	$rq = "OPTIONS $path HTTP/1.1\r\n".
	    "Host: $hostname\r\n".
	    "Upgrade: TLS/1.0\r\n".
	    "Connection: Upgrade\r\n".
	    "\r\n";
    }
    print $cl $rq;
    my $hdr = _readlines($cl,qr/\r?\n/);
    $hdr =~m{\A(HTTP/1\.[01]\s+(\d\d\d)[^\r\n]*)};
    die "upgrade not accepted, code=$2 (expect 101): $1" if $2 != 101;
    VERBOSE(3,"...tls upgrade request: $1");
    return $cl;
}

sub ftp_auth {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    my $last_status_line = qr/((\d)\d\d(?:\s.*)?)/;
    my ($line,$code) = _readlines($cl,$last_status_line);
    die "server denies access: $line\n" if $code != 2;
    print $cl "AUTH TLS\r\n";
    ($line,$code) = _readlines($cl,$last_status_line);
    die "AUTH TLS denied: $line\n" if $code != 2;
    VERBOSE(3,"...ftp auth: $line");
    return $cl;
}

sub postgresql_init {
    my $cl = $ioclass->new(%{shift()}) or die "tcp connect: $!";
    # magic header to initiate SSL:
    # http://www.postgresql.org/docs/devel/static/protocol-message-formats.html
    print $cl pack("NN",8,80877103);
    read($cl, my $buf,1 ) or die "did not get response from postgresql";
    $buf eq 'S' or die "postgresql does not support SSL (response=$buf)";
    VERBOSE(3,"...postgresql supports SSL: $buf");
    return $cl;
}

sub _readlines {
    my ($cl,$stoprx) = @_;
    my $buf = '';
    while (<$cl>) {
	$buf .= $_;
	return $buf if ! $stoprx;
	next if ! m{\A$stoprx\Z};
	return ( m{\A$stoprx\Z},$buf );
    }
    die "eof" if $buf eq '';
    die "unexpected response: $buf";
}



sub VERBOSE {
    my $level = shift;
    $verbose>=$level || return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    my $prefix = $level == 1 ? '+ ' : $level == 2 ? '* ' : "<$level> ";
    print STDERR "$prefix$msg\n";
}
