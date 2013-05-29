#!/usr/bin/perl
# simple HTTPS proxy with SSL bridging, uses Net::PcapWriter to
# to log unencrypted traffic

my $listen = '127.0.0.1:8443';      # where to listen
my $connect = 'www.google.com:443'; # where to connect
my $proxy_cert_pem = <<'PEM';
-----BEGIN CERTIFICATE-----
MIICWDCCAcGgAwIBAgIJAI8FHB/c/bcHMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTMwNTI5MDc0NTUwWhcNMTMwNjI4MDc0NTUwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDB34KkCuSoRm0HLyvofujRFM6RFgp5VA41GGVVU9Wuun2GEmloAQUnfowIRGCB
ph5txxq/DJjSk5U/pDAM1K/uG6OTSEondn3F1CQb9HSn4oklys+E7nEQaXulLdz5
reCMjw7rJC1PXke53x8vMaQ3gTy1/uMXauXfkb9L6ZdOvwIDAQABo1AwTjAdBgNV
HQ4EFgQUy0SgP5Whtu3pk3IpvFx/V4AO63UwHwYDVR0jBBgwFoAUy0SgP5Whtu3p
k3IpvFx/V4AO63UwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQBTdci1
iDsuQJ+i3YtBckWhow3ACKwLrexP3ElwByLyS80NfcSuauXm5E71q8yn0+QMUNZS
9l0HI3kz/37O1BVV45G+DTVqHN0kFrRVXZMwc6ruU1ugPjzUn+I34SDWPVPqfH9n
a9MnXP+HupvhHtF5vya+tuxsquzsXD5xrBOlKQ==
-----END CERTIFICATE-----
PEM
my $proxy_key_pem = <<'PEM';
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDB34KkCuSoRm0HLyvofujRFM6RFgp5VA41GGVVU9Wuun2GEmlo
AQUnfowIRGCBph5txxq/DJjSk5U/pDAM1K/uG6OTSEondn3F1CQb9HSn4oklys+E
7nEQaXulLdz5reCMjw7rJC1PXke53x8vMaQ3gTy1/uMXauXfkb9L6ZdOvwIDAQAB
AoGAOIylYov63kqMisfrmslJx5K2HgO70l/+NOaEyDrH3UtwSacdL8T8Z+S1m8O2
EpsNzR+CYa+e8+0wX3vYuCVhmyNiBztWk2D4+pRCQfyNSVXWyokjdTXbPii+rL9o
WXqud0V0mCwDteWbU54rtvAL5EAdG8pNnP+Tl6h86wADaCECQQD8aMqubnQYzBuS
d4zTNznFncp5lqQXq6qUW4vghS/CYNYI7ZmrE+cae1B4AThab+5BSyZpg4+dc9vK
7JFyVqQLAkEAxKGLg/p3NyyOK6WC/GUm7ucsZJZE1Q0EgAx5G1l9tMDg81tBt0r8
QTX6LRy3okuH0RgGFUYmFEECtEfw/DqcnQJAZwpYg3Dv0Beywc4wHSGUYgoSWCSZ
BFi+ICZnKdb1MkLZ3XcxnldXpsXkibjlynWbK+iD29srS7m6ZlLA5Y5dFQJAL3Jj
vfcEKVYhADsx/kFSQbeaqLLx7Q71FQjteEIB6UnZfh95HgeEEyA5PAV/8jOTlErd
vOhua9i8FFB/v/1MqQJAfr7mssqwRh/XsN9UWpnVmwj/goWb1xWuNlbTTLiyCCKu
rilsvUp/HEMI9aKAmmxaHGe0TyLSW+p3HVKEKmnV4A==
-----END RSA PRIVATE KEY-----
PEM

use strict;
use warnings;
use IO::Socket::SSL;
use File::Temp 'tempfile';

my ($fh,$proxy_cert_file) = tempfile('certXXXX', CLEANUP => 1);
print $fh $proxy_cert_pem;
($fh,my $proxy_key_file) = tempfile('keyXXXX', CLEANUP => 1);
print $fh $proxy_key_pem;
close($fh);

my $mitm = IO::Socket::SSL::Intercept->new(
    proxy_cert_file => $proxy_cert_file,
    proxy_key_file => $proxy_key_file,
);

my $listener = IO::Socket::INET->new(
    LocalAddr => $listen,
    Listen => 10,
    Reuse => 1,
) or die "failed to create listener: $!";

while (1) {
    # get connection from client
    my $toc = $listener->accept or next;

    # create new connection to server
    my $tos = IO::Socket::SSL->new(
	PeerAddr => $connect,
	SSL_verify_mode => 1,
	SSL_ca_path => '/etc/ssl/certs',
    ) or die "ssl connect to $connect failed: $!,$SSL_ERROR";

    # clone cert from server
    my ($cert,$key) = $mitm->clone_cert( $tos->peer_certificate );

    # and upgrade connection to client to SSL with cloned cert
    IO::Socket::SSL->start_SSL($toc,
	SSL_server => 1,
	SSL_cert => $cert,
	SSL_key => $key,
    ) or die "failed to ssl upgrade: $SSL_ERROR";

    # transfer data
    my $readmask = '';
    vec($readmask,fileno($tos),1) = 1;
    vec($readmask,fileno($toc),1) = 1;
    while (1) {
	select( my $can_read = $readmask,undef,undef,undef ) >0 or die $!;
	if ( vec($can_read,fileno($tos),1)) {
	    sysread($tos,my $buf,100) or last;
	    print $toc $buf;
	}
	if ( vec($can_read,fileno($toc),1)) {
	    sysread($toc,my $buf,100) or last;
	    print $tos $buf;
	}
    }
}
    
    
