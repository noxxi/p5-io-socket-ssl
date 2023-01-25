#
# a test server for testing IO::Socket::SSL-class's behavior

use strict;
use warnings;
use IO::Socket::SSL;
use Getopt::Long qw(:config posix_default bundling);
use Digest::MD5 'md5_hex';

my ($cert_file,$key_file,$key_pass,$ca,$http);
GetOptions(
    'd|debug:i' => \$IO::Socket::SSL::DEBUG,
    'h|help'    => sub { usage() },
    'C|cert=s'  => \$cert_file,
    'K|key=s'   => \$key_file,
    'P|pass=s'  => \$key_pass,
    'ca=s'      => \$ca,
    'http'      => \$http,
) or usage("bad option");

sub usage {
    print STDERR "Error: @_\n" if @_;
    print STDERR <<USAGE;
Usage: $0 [options] ip:port
ip:port - where to listen
Options:
  -d|--debug [level]      enable debugging with optional debug level
  -h|--help               this help
  -C|--cert  cert-file    file containing certificate
  -K|--key   key-file     file containing private key, default cert-file
  -P|--pass  passphrase   passphrase for private key, default none
  --ca dir|file           request a client certificate and use given dir/file as 
                          trusted CA store to verify it
  --http                  work as tiny HTTP server
USAGE
    exit(2);
}

my $addr = shift(@ARGV) or usage("no listen address given");
@ARGV and usage("too much arguments");
$cert_file or usage("no certificate given");
$key_file ||= $cert_file;

my $server = IO::Socket::IP->new(
    Listen => 5,
    LocalAddr => $addr,
    ReuseAddr => 1,
) or die "failed to create SSL server at $addr: $!";

my $ctx = IO::Socket::SSL::SSL_Context->new(
    SSL_server => 1,
    SSL_cert_file => $cert_file,
    SSL_key_file  => $key_file,
    defined($key_pass) ? ( SSL_passwd_cb => sub { $key_pass } ):(),
    $ca ? (
	SSL_verify_mode => SSL_VERIFY_PEER,
	-d $ca ? ( SSL_ca_path => $ca ):( SSL_ca_file => $ca, SSL_client_ca_file => $ca )
    ):(),
) or die "cannot create context: $SSL_ERROR";

while (1) {
    warn "waiting for next connection.\n";
    my $cl = $server->accept or do {
	warn "failed to accept: $!\n";
	next;
    };

    IO::Socket::SSL->start_SSL($cl,
	SSL_server => 1,
	SSL_reuse_ctx => $ctx,
	SSL_startHandshake => 0
    ) or do {
	warn "ssl handshake failed: $SSL_ERROR\n";
	next;
    };

    my $ja3;
    $cl->set_msg_callback(\&msgcb, \$ja3);
    $cl->accept_SSL() or do {
	warn "failed SSL handshake: $SSL_ERROR\n";
	next;
    };

    my $info = "cipher=".$cl->get_cipher
	. " version=".$cl->get_sslversion
	. " ja3=".md5_hex($ja3)." $ja3";

    if ( $cl->peer_certificate ) {
	warn "new SSL connection with client certificate\n".
	    "\tsubject=".$cl->peer_certificate('subject')."\n".
	    "\tissuer=".$cl->peer_certificate('issuer')."\n".
	    $info."\n";
    } else {
	warn "new SSL connection without client certificate\n".
	    $info."\n";
    }

    if ($http) {
	sysread($cl, my $buf, 8192);
	$buf =~s{\n\r?\n.*}{\n}s;
	$info =~s{\b\w+=}{\n$&}mg;
	$info .= "\n\n-------\n\n$buf";
	print $cl "HTTP/1.0 200 ok\r\n".
	    "Content-type: text/plain\r\n".
	    "Content-length: ".length($info)."\r\n".
	    "\r\n".
	    $info;
    } else {
	print $cl "connect with $info\n";
    }
}


sub msgcb {
    my ($self, $direction, $ssl_ver, $content_type, $buf, $len, $ssl, $ja3_r) = @_;
    $content_type == 22 or return;  # TLS handshake
    #  1 byte: msg type
    #  3 byte: length
    (my $msg_type, $buf) = unpack('c x3 a*', $buf);
    if ($msg_type == 1)  {      # Client Hello
	$self->set_msg_callback(undef);  # no need to look further

	my %grease = map { $_ =>1 } (
	    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	);

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

	$$ja3_r = join(",",
	    $ver,
	    join("-", @ciphers),
	    join("-", @ext),
	    join("-", @elliptic_curve),
	    join("-", @elliptic_curve_point_format),
	);
    }
}
