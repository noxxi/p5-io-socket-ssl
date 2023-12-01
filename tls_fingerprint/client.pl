use strict;
use warnings;
use IO::Socket::SSL;
use lib '.';
use JAX qw(ja3 ja4 ja3s);

for my $dst (@ARGV) {
    my $cl = IO::Socket::SSL->new(
	PeerAddr => $dst,
	PeerPort => 443,
	SSL_startHandshake => 0,
	#SSL_version => 'TLSv1_2',
    ) or die $!;

    my ($chello, $shello);
    $cl->set_msg_callback(\&msgcb, \$chello, \$shello);
    $cl->connect_SSL() or die $SSL_ERROR;

    print "JA3       ".ja3($chello)."\n";
    print "JA3 raw   ".ja3($chello,1)."\n";
    print "JA3N      ".ja3($chello,0,1)."\n";
    print "JA3N raw  ".ja3($chello,1,1)."\n";
    print "JA4       ".ja4($chello)."\n";
    print "JA4 raw   ".ja4($chello,1)."\n";
    print "JA4_o     ".ja4($chello,0,0)."\n";
    print "JA4_o raw ".ja4($chello,1,0)."\n";
    print "JA3S      ".ja3s($shello)."\n";
    print "JA3S  raw ".ja3s($shello,1)."\n";
    print "JA3SN     ".ja3s($shello,0,1)."\n";
    print "JA3SN raw ".ja3s($shello,1,1)."\n";
}


sub msgcb {
    my ($self, $direction, $ssl_ver, $content_type, $buf, $len, $ssl, $chello_r, $shello_r) = @_;
    $content_type == 22 or return;  # TLS handshake
    #  1 byte: msg type
    #  3 byte: length
    (my $msg_type, $buf) = unpack('c x3 a*', $buf);
    if ($msg_type == 1)  {      # Client Hello
	$$chello_r = $buf;
    } elsif ($msg_type == 2) {  # Server Hello
	$self->set_msg_callback(undef);  # no need to look further
	$$shello_r = $buf;
    }
}
