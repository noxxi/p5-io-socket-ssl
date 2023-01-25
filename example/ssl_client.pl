#
# a test client for testing IO::Socket::SSL-class's behavior

use strict;
use warnings;
use IO::Socket::SSL;
use Getopt::Long qw(:config posix_default bundling);
use Digest::MD5 'md5_hex';

my ($cert_file,$key_file,$key_pass,$ca,$name,$no_verify);
GetOptions(
    'd|debug:i' => \$IO::Socket::SSL::DEBUG,
    'h|help'    => sub { usage() },
    'C|cert=s'  => \$cert_file,
    'K|key=s'   => \$key_file,
    'P|pass=s'  => \$key_pass,
    'ca=s'      => \$ca,
    'name=s'    => \$name,
    'no-verify' => \$no_verify,
) or usage("bad option");

sub usage {
    print STDERR "Error: @_\n" if @_;
    print STDERR <<USAGE;
Usage: $0 [options] ip:port
ip:port - where to connect to
Options:
  -d|--debug [level]      enable debugging with optional debug level
  -h|--help               this help
  -C|--cert  cert-file    file containing optional client certificate
  -K|--key   key-file     file containing private key to certificate, default cert-file
  -P|--pass  passphrase   passphrase for private key, default none
  --ca dir|file           use given dir/file as trusted CA store
  --name hostname         use hostname for SNI and certificate check
  --no-verify             don't verify certificate
USAGE
    exit(2);
}

my $addr = shift(@ARGV) or usage("no target address given");
@ARGV and usage("too much arguments");
$key_file ||= $cert_file;

my $cl = IO::Socket::SSL->new(
    PeerAddr => $addr,
    $ca ? ( -d $ca ? ( SSL_ca_path => $ca ):( SSL_ca_file => $ca ) ):(),
    $name ? ( SSL_hostname => $name ):(),
    $no_verify ? ( SSL_verify_mode => 0 ):(),
    $cert_file ? (
	SSL_cert_file => $cert_file,
	SSL_key_file  => $key_file,
	defined($key_pass) ? ( SSL_passwd_cb => sub { $key_pass } ):(),
    ):(),
    SSL_startHandshake => 0,
) or die "failed to connect to $addr: $!,$SSL_ERROR";

my $ja3s;
$cl->set_msg_callback(\&msgcb, \$ja3s);
$cl->connect_SSL() or die "failed SSL handshake: $SSL_ERROR";

warn "new SSL connection with cipher=".$cl->get_cipher." version=".$cl->get_sslversion." certificate:\n".
    "\tsubject=".$cl->peer_certificate('subject')."\n".
    "\tissuer=".$cl->peer_certificate('issuer')."\n".
    "\tja3s=".md5_hex($ja3s)." $ja3s\n";


sub msgcb {
    my ($self, $direction, $ssl_ver, $content_type, $buf, $len, $ssl, $ja3s_r) = @_;
    $content_type == 22 or return;  # TLS handshake
    #  1 byte: msg type
    #  3 byte: length
    (my $msg_type, $buf) = unpack('c x3 a*', $buf);
    if ($msg_type == 2) {  # Server Hello
	$self->set_msg_callback(undef);  # no need to look further

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
	    push @ext, $ext_type;
	}
	$$ja3s_r = join(",",
	    $ver,
	    $cipher,
	    join("-", @ext)
	);
    }
}
