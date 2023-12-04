# Copyright Steffen Ullrich 2023
# License: public domain (no restrictions)

use strict;
use warnings;
use IO::Socket::SSL;
use IO::Socket::SSL::Utils;
use IO::Socket::IP;
use lib '.';
use JAX qw(ja3 ja4 ja3s);

my $addr = $ARGV[0] || "127.0.0.1:4433";
my $srv = IO::Socket::IP->new(
    LocalAddr => $addr,
    Listen => 10,
    Reuse => 1,
) or die "failed to listen on $addr: $!";

my $cert_and_key = do { local $/; <DATA> };
my $ctx = IO::Socket::SSL::SSL_Context->new(
    SSL_cert => PEM_string2cert($cert_and_key),
    SSL_key => PEM_string2key($cert_and_key),
    SSL_server => 1,
    SSL_cipher_list => 'DEFAULT:@SECLEVEL=0',
    SSL_version => 'SSLv23',
) or die "failed to create SSL context: $SSL_ERROR";

print STDERR "Listening on $addr\n";


while (1) {
    my $cl = $srv->accept or next;
    $cl = IO::Socket::SSL->start_SSL($cl,
	SSL_server => 1,
	SSL_reuse_ctx => $ctx,
	SSL_startHandshake => 0,
    ) or die $!;

    my ($chello, $shello);
    $cl->set_msg_callback(\&msgcb, \$chello, \$shello);
    $cl->accept_SSL() or die "SSL handshake failed: $SSL_ERROR";

    print "--- accept from ".$cl->peerhost.":".$cl->peerport."\n";
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

__DATA__
-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIFANkVla8wDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAwwX
SU86OlNvY2tldDo6U1NMIERlbW8gQ0EwHhcNMjIxMjExMTk1MzQxWhcNMzIxMjA4
MTk1MzQxWjAXMRUwEwYDVQQDDAxzZXJ2ZXIubG9jYWwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCnMcTzSybDMjCCFTfPPzOltpavJ1cvOQ4X99q7jQph
2dTGx1feefwcuKJl3eEuwiV/y6MWWkjJVC1vICSu2BuBhL76jCgl0mKIQbN3jVpS
KtqnytRGVvGvB3AP71RMzRXaI0xiwRsjvXnBhliTaYBtbpVqry1Cx7eouxeveRxx
3+5dfBNU0i9U18EZPl99Yl2z2Z6OvzT0ULJl9cWP90UKrX16G5eH8vHrMwm02rpn
i+7u0o7O9a7/xQV28cSoEgp2Cnbg0ZUXbmQS4aYDqIkpS2GlOL8eV26KvM2hYX7h
qy0CsrjJ4riJd+YhmGRsPH3DBGjB/kRX8NhAP2+tblc/AgMBAAGjgagwgaUwHQYD
VR0OBBYEFHW7Ml+/HDstKVpiCxHde7b+VttWMB8GA1UdIwQYMBaAFEnT2LwqEtZv
wVkEbtlv/7SmEt9cMB0GA1UdEQQWMBSCDHNlcnZlci5sb2NhbIcEfwAAATAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDARBglghkgBhvhCAQEEBAMCBkAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAKA5/2fl2oRtBnUj
Zr+a2Z1uc+oTP03VPT/w46uolz27MqgQyBiSX+a2WWFWZJZFDK6jv3Yd1C7j+KOm
V7sbHOhoIGDwQC55vwdlc5r72RYZOuZSFtujvaABEZ+vF8AHnI3PbiShedL/bK2N
yZYWtBj4Lbl1Hb9I+AjOY5TJ5zcenyS5hIEYXZgV0NH5Thf4zMIKrRZ6//3XcN5n
zT7nMyPTqh0nYIAblmOKvYu6RJQ29BL8FyNmNXjItr3HjaKIxZry7apvwrHBt+a7
bLQzc5e8/cb06gTHZJYdsWDBT6Mv81jNFA/d2OEbpWCNH4ySLPHCBItMmWTxZR87
D7hgP1A=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnMcTzSybDMjCC
FTfPPzOltpavJ1cvOQ4X99q7jQph2dTGx1feefwcuKJl3eEuwiV/y6MWWkjJVC1v
ICSu2BuBhL76jCgl0mKIQbN3jVpSKtqnytRGVvGvB3AP71RMzRXaI0xiwRsjvXnB
hliTaYBtbpVqry1Cx7eouxeveRxx3+5dfBNU0i9U18EZPl99Yl2z2Z6OvzT0ULJl
9cWP90UKrX16G5eH8vHrMwm02rpni+7u0o7O9a7/xQV28cSoEgp2Cnbg0ZUXbmQS
4aYDqIkpS2GlOL8eV26KvM2hYX7hqy0CsrjJ4riJd+YhmGRsPH3DBGjB/kRX8NhA
P2+tblc/AgMBAAECggEABJVkCtodPpivpRaj0wtZL8p+UwrxuZpc0oy5nblTdt9G
lV8oVNxklvz7fBjFxZxjnsnxt05+VFakcDl3XVEQtU+dqgy8RQfW1QQdbBefSZq3
J9vIT1gELteLW5nPZn5GLRbD+f5v7147FPJz7Ial6K9xaof8O6px/y7cirOinf80
Ll73KxTyb7amgAxJS34/STSHvBGUu0RYUQWX7cXllqONn+zZ+fgiertwervHYH+7
rkcbAsG3AGZtXJ20K20qOmc5QvtIdu0OGvRdW861ZYCNgEcUaeO7Lvt9CrOZyhUe
lqGw22cxJevIPUEoJY4gyNY3SV/WmqG+QKOIK4IuMQKBgQDoqpVvkp3Q47GsG6Dr
skTgIv9Aof7/4fv9dHNYWYaUzQMGW2uxr7Dy6yuvhkplwjVTYxmZrwcKeT0L4wuu
ofhSPRKH7h4o3CVZI9QSz6hrk15u9oKvqmN9W5FOj5ZaXxcdT1NHVENGMYl08E2J
dzLgTJPFPnCEWiZKEE0QSLW4LQKBgQC39kalXeDAMDXR7Db0ui1Wgfc0hL0NuDim
HrzmgtZrZCoYZLjvm1pYQ0sxZ/8S97oh3HKTZh83plbmDQzTRjgSJTGLp0utRTuY
2TuyJURurX2SJggg+6yL0o2eS1yA4t1Mb2onr49o4DSeEggRML9hAY3Ihg2cTYiy
ImTQ8vekmwKBgC+4nUHvLpNjwFNur0jonZvjUbtt/qF5Nng75FSguCvZCN/K7IHb
aU3J0oID50qL1OgvkVamQalySIUhoonFCuvDPwPGYUU8MiTgZmUdVowKA/p6cT+a
kSFrIJiedtY+Xr1SQeCFde71xh3IE/84BaVfz4dLUUS0QNo8EbJfV3ZZAoGACbwS
iPWqywDCGFWzosenVoiSGEld57fz53aA8IHD7vLh92B9GNDTuw/0jqy+JrbNNrV/
qqUgycUXnBzcrOFuXidxs74qlwSu3qvAKPEn6eNsXat9iqFGxC9kJxg90OQwabcL
mwYDRL14i1TQ8Hfv6KY4ZoARgE/qB+MiCpyQ1jkCgYAD3jMZAYaxp11Zl0qxffCT
AQZkah+tTA8tC0TYSNxUUq18nnU8gvLuIF8YUt/HJkFajA9GQkA0rg+KUZ3ig3n2
VfwHCMf0HGH90jc9wRQRd0FlkaAn68e5t3/eCAoQFnN65iit+ODR8isqTqRISMJt
nL6o91SHe9luE7bU49fnVQ==
-----END PRIVATE KEY-----
