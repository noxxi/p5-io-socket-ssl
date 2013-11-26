
package IO::Socket::SSL::Utils;
use strict;
use warnings;
use Carp 'croak';
use Net::SSLeay;
use Time::Local;
use Exporter 'import';

our $VERSION = '0.02';
our @EXPORT = qw(
    PEM_file2cert PEM_string2cert PEM_cert2file PEM_cert2string
    PEM_file2key PEM_string2key PEM_key2file PEM_key2string
    KEY_free CERT_free
    KEY_create_rsa CERT_asHash CERT_create
);

sub PEM_file2cert {
    my $file = shift;
    my $bio = Net::SSLeay::BIO_new_file($file,'r') or
	croak "cannot read $file: $!";
    my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or croak "cannot parse $file as PEM X509 cert: ".
	Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    return $cert;
}

sub PEM_cert2file {
    my ($cert,$file) = @_;
    my $string = Net::SSLeay::PEM_get_string_X509($cert)
	or croak("cannot get string from cert");
    open( my $fh,'>',$file ) or croak("cannot write $file: $!");
    print $fh $string;
}

sub PEM_string2cert {
    my $string = shift;
    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio,$string);
    my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or croak "cannot parse string as PEM X509 cert: ".
	Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    return $cert;
}

sub PEM_cert2string {
    my $cert = shift;
    return Net::SSLeay::PEM_get_string_X509($cert)
	|| croak("cannot get string from cert");
}

sub PEM_file2key {
    my $file = shift;
    my $bio = Net::SSLeay::BIO_new_file($file,'r') or
	croak "cannot read $file: $!";
    my $cert = Net::SSLeay::PEM_read_bio_PrivateKey($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or croak "cannot parse $file as PEM private key: ".
	Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    return $cert;
}

sub PEM_key2file {
    my ($key,$file) = @_;
    my $string = Net::SSLeay::PEM_get_string_PrivateKey($key)
	or croak("cannot get string from key");
    open( my $fh,'>',$file ) or croak("cannot write $file: $!");
    print $fh $string;
}

sub PEM_string2key {
    my $string = shift;
    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem());
    Net::SSLeay::BIO_write($bio,$string);
    my $cert = Net::SSLeay::PEM_read_bio_PrivateKey($bio);
    Net::SSLeay::BIO_free($bio);
    $cert or croak "cannot parse string as PEM private key: ".
	Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    return $cert;
}

sub PEM_key2string {
    my $key = shift;
    return Net::SSLeay::PEM_get_string_PrivateKey($key)
	|| croak("cannot get string from key");
}

sub CERT_free {
    my $cert = shift or return;
    Net::SSLeay::X509_free($cert);
}

sub KEY_free {
    my $key = shift or return;
    Net::SSLeay::EVP_KEY_free($key);
}

sub KEY_create_rsa {
    my $bits = shift || 1024;
    my $key = Net::SSLeay::EVP_PKEY_new();
    my $rsa = Net::SSLeay::RSA_generate_key(1024, 0x10001); # 0x10001 = RSA_F4
    Net::SSLeay::EVP_PKEY_assign_RSA($key,$rsa);
    return $key;
}

# extract information from cert
my %gen2i = qw( OTHERNAME 0 EMAIL 1 DNS 2 X400 3 DIRNAME 4 EDIPARTY 5 URI 6 IP 7 RID 8 );
my %i2gen = reverse %gen2i;
sub CERT_asHash {
    my $cert = shift;

    my %hash = (
	version => Net::SSLeay::X509_get_version($cert),
	not_before => _asn1t2t(Net::SSLeay::X509_get_notBefore($cert)),
	not_after => _asn1t2t(Net::SSLeay::X509_get_notAfter($cert)),
	serial => Net::SSLeay::ASN1_INTEGER_get(
	    Net::SSLeay::X509_get_serialNumber($cert)),
    );

    my $subj = Net::SSLeay::X509_get_subject_name($cert);
    my %subj;
    for ( 0..Net::SSLeay::X509_NAME_entry_count($subj)-1 ) {
	my $e = Net::SSLeay::X509_NAME_get_entry($subj,$_);
	my $o = Net::SSLeay::X509_NAME_ENTRY_get_object($e);
	$subj{ Net::SSLeay::OBJ_obj2txt($o) } =
	    Net::SSLeay::P_ASN1_STRING_get(
		Net::SSLeay::X509_NAME_ENTRY_get_data($e));
    }
    $hash{subject} = \%subj;

    if ( my @names = Net::SSLeay::X509_get_subjectAltNames($cert) ) {
	my $alt = $hash{subjectAltNames} = [];
	while (my ($t,$v) = splice(@names,0,2)) {
	    $t = $i2gen{$t} || die "unknown type $t in subjectAltName";
	    if ( $t eq 'IP' ) {
		if (length($v) == 4) {
		    $v = join('.',unpack("CCCC",$v));
		} elsif ( length($v) == 16 ) {
		    $v = join(':',map { sprintf( "%x",$_) } unpack("NNNN",$v));
		}
	    }
	    push @$alt,[$t,$v]
	}
    }

    return \%hash;
}

my $sha1_digest;
sub CERT_create {
    my %args = @_%2 ? %{ shift() } :  @_;

    my $cert = Net::SSLeay::X509_new();
    $sha1_digest ||= do {
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::EVP_get_digestbyname("sha1")
	    or die "SHA1 not available";
    };

    Net::SSLeay::ASN1_INTEGER_set(
	Net::SSLeay::X509_get_serialNumber($cert),
	delete $args{serial} || rand(2**32),
    );

    # version default to 2 (V3)
    Net::SSLeay::X509_set_version($cert,
	delete $args{version} || 2 );

    # not_before default to now
    Net::SSLeay::ASN1_TIME_set(
	Net::SSLeay::X509_get_notBefore($cert),
	delete $args{not_before} || time()
    );

    # not_after default to now+365 days
    Net::SSLeay::ASN1_TIME_set(
	Net::SSLeay::X509_get_notAfter($cert),
	delete $args{not_after} || time() + 365*86400
    );

    # set subject
    my $subj_e = Net::SSLeay::X509_get_subject_name($cert);
    my $subj = delete $args{subject} || {
	organizationName => 'IO::Socket::SSL',
	commonName => 'IO::Socket::SSL Test'
    };
    while ( my ($k,$v) = each %$subj ) {
	# 0x1000 = MBSTRING_UTF8
	Net::SSLeay::X509_NAME_add_entry_by_txt($subj_e,
	    $k, 0x1000, $v, -1, 0)
	    or croak("failed to add entry for $k - ".
	    Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error()));
    }

    my @ext = (
	&Net::SSLeay::NID_subject_key_identifier => 'hash',
	&Net::SSLeay::NID_authority_key_identifier => 'keyid',
	&Net::SSLeay::NID_authority_key_identifier => 'issuer',
    );
    if ( my $altsubj = delete $args{subjectAltNames} ) {
	push @ext,
	    &Net::SSLeay::NID_subject_alt_name =>
	    join(',', map { "$_->[0]:$_->[1]" } @$altsubj)
    }

    my $key = delete $args{key} || KEY_create_rsa();
    Net::SSLeay::X509_set_pubkey($cert,$key);

    my $issuer_cert = delete $args{issuer_cert};
    my $issuer_key  = delete $args{issuer_key};
    if ( delete $args{CA} ) {
	$issuer_cert ||= $cert;
	$issuer_key  ||= $key;
	push @ext, &Net::SSLeay::NID_basic_constraints => 'CA:TRUE',

    } else {
	$issuer_cert || croak "no issuer_cert given";
	$issuer_key  || croak "no issuer_key given";
	push @ext,
	    &Net::SSLeay::NID_key_usage => 'digitalSignature,keyEncipherment',
	    &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
	    &Net::SSLeay::NID_ext_key_usage => 'serverAuth,clientAuth',
	    &Net::SSLeay::NID_netscape_cert_type => 'server';
    }

    Net::SSLeay::P_X509_add_extensions($cert, $issuer_cert, @ext);
    Net::SSLeay::X509_set_issuer_name($cert,
	Net::SSLeay::X509_get_subject_name($issuer_cert));
    Net::SSLeay::X509_sign($cert,$issuer_key,$sha1_digest);

    return ($cert,$key);
}



my %mon2i = qw(
    Jan 0 Feb 1 Mar 2 Apr 3 May 4 Jun 5
    Jul 6 Aug 7 Sep 8 Oct 9 Nov 10 Dec 11
);
sub _asn1t2t {
    my $t = Net::SSLeay::P_ASN1_TIME_put2string( shift );
    my ($mon,$d,$h,$m,$s,$y) = split(/[\s:]+/,$t);
    defined( $mon = $mon2i{$mon} ) or die "invalid month in $t";
    my $tz = $y =~s{^(\d+)([A-Z]\S*)}{$1} && $2;
    if ( ! $tz ) {
	return timelocal($s,$m,$h,$d,$mon,$y)
    } elsif ( $tz eq 'GMT' ) {
	return timegm($s,$m,$h,$d,$mon,$y)
    } else {
	die "unexpected TZ $tz from ASN1_TIME_print";
    }
}


1;

__END__

=head1 NAME

IO::Socket::SSL::Utils -- loading, storing, creating certificates and keys

=head1 SYNOPSIS

    use IO::Socket::SSL::Utils;
    my $cert = PEM_file2cert('cert.pem');
    my $string = PEM_cert2string($cert);
    CERT_free($cert);

    my $key = KEY_create_rsa(2048);
    PEM_string2file($key);
    KEY_free($key);


=head1 DESCRIPTION

This module provides various utility functions to work with certificates and
private keys, shielding some of the complexity of the underlying Net::SSLeay and
OpenSSL.

=head1 FUNCTIONS

=over 4

=item *

Functions converting between string or file and certificates and keys.
They croak if the operation cannot be completed.

=over 8

=item PEM_file2cert(file) -> cert

=item PEM_cert2file(cert,file)

=item PEM_string2cert(string) -> cert

=item PEM_cert2string(cert) -> string

=item PEM_file2key(file) -> key

=item PEM_key2file(key,file)

=item PEM_string2key(string) -> key

=item PEM_key2string(key) -> string

=back

=item *

Functions for cleaning up.
Each loaded or created cert and key must be freed to not leak memory.

=over 8

=item CERT_free(cert)

=item KEY_free(key)

=back

=item * KEY_create_rsa(bits) -> key

Creates an RSA key pair, bits defaults to 1024.

=item * CERT_asHash(cert) -> hash

Extracts the information from the certificate into a hash:

=over 8

=item serial

The serial number

=item version

Certificate version, usually 2 (x509v3)

=item subject

Hash with the parts of the subject, e.g. commonName, countryName,
organizationName, stateOrProvinceName, localityName.

=item subjectAltNames

Array with list of alternative names. Each entry in the list is of
C<[type,value]>, where C<type> can be OTHERNAME, EMAIL, DNS, X400, DIRNAME,
EDIPARTY, URI, IP or RID.

=item not_before, not_after

The time frame, where the certificate is valid, as time_t, e.g. can be converted
with localtime or similar functions.

=back

=item * CERT_create(hash) -> (cert,key)

Creates a certificate based on the given hash.
Additionally to the information described in C<CERT_asHash> the following keys
can be given:

=over 8

=item CA true|false

if true declare certificate as CA, defaults to false

=item key key

use given key as key for certificate, otherwise a new one will be generated and
returned

=item issuer_cert cert

set issuer for new certificate

=item issuer_key key

sign new certificate with given key

=back

If not all necessary information are given some will have usable defaults, e.g.

=over 8

=item not_before defaults to the current time

=item not_after defaults to 365 days in the future

=item subject has a default pointing to IO::Socket::SSL

=item version defaults to 2 (x509v3)

=item serial will be a random number

=back

=back

=head1 AUTHOR

Steffen Ullrich
