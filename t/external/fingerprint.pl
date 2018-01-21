# to update fingerprints in this file:
# perl -e 'do q[t/external/fingerprint.pl]; update_fingerprints()'

use strict;
use warnings;
use IO::Socket::SSL;

# --- BEGIN-FINGERPRINTS ----
my $fingerprints= [
  {
    _ => 'this should give us OCSP stapling',
    fingerprint => 'sha1$pub$39d64bbaea90c6035e25ff990ba4ce565350bac5',
    host => 'www.chksum.de',
    ocsp => {
              staple => 1
            },
    port => 443
  },
  {
    _ => 'no OCSP stapling',
    fingerprint => 'sha1$pub$f8c51d37c070c423ccc5f6065e080b94ce03494c',
    host => 'www.bild.de',
    ocsp => {
              staple => 0
            },
    port => 443,
    subject_hash_ca => 'e2799e36'
  },
  {
    _ => 'this is revoked',
    fingerprint => 'sha1$pub$75f8bfe5feac656c894c06011422b6455854b4e5',
    host => 'revoked.grc.com',
    ocsp => {
              revoked => 1
            },
    port => 443
  },
  {
    fingerprint => 'sha1$pub$92447765c3dde2634366d661b86810f301961c9b',
    host => 'www.yahoo.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$83ac9a7311a410d3d819a45ec1f7460c7adfe4c0',
    host => 'www.comdirect.de',
    port => 443,
    subject_hash_ca => '02265526'
  },
  {
    fingerprint => 'sha1$pub$458e905cd62b9ce9f8c5eb7298f62871de89c81f',
    host => 'meine.deutsche-bank.de',
    port => 443,
    subject_hash_ca => 'c01cdfa2'
  },
  {
    fingerprint => 'sha1$pub$9f627bb2880eee1b79e06924e5ba3f47a60b02f0',
    host => 'www.twitter.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$c0fd74f57dcbc627f103d362a245d7841c152108',
    host => 'www.facebook.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$0a2a638d8484c2be34fd9534cf111d48b91885b0',
    host => 'www.live.com',
    port => 443,
    subject_hash_ca => '653b494a'
  }
]
;
# --- END-FINGERPRINTS ----


sub update_fingerprints {
    my $changed;
    for my $fp (@$fingerprints) {
	my $cl = IO::Socket::INET->new(
	    PeerHost => $fp->{host},
	    PeerPort => $fp->{port} || 443,
	    Timeout => 10,
	);
	my $root;
	if (!$cl) {
	    warn "E $fp->{host}:$fp->{port} - TCP connect failed: $!\n";
	} elsif (!IO::Socket::SSL->start_SSL($cl,
	    Timeout => 10,
	    SSL_ocsp_mode => 0,
	    SSL_hostname => $fp->{host},
	    SSL_verify_callback => sub {
		my ($cert,$depth) = @_[4,5];
		$root ||= $cert;
		return 1;
	    }
	)) {
	    warn "E $fp->{host}:$fp->{port} - SSL handshake failed: $SSL_ERROR\n";
	} else {
	    my $sha1 = $cl->get_fingerprint('sha1',undef,1);
	    if ($sha1 eq $fp->{fingerprint}) {
		warn "N $fp->{host}:$fp->{port} - fingerprint as expected\n";
	    } else {
		warn "W $fp->{host}:$fp->{port} - fingerprint changed from $fp->{fingerprint} to $sha1\n";
		$fp->{fingerprint} = $sha1;
		$changed++;
	    }
	    if ($root and $fp->{subject_hash_ca}) {
		my $hash = sprintf("%08x",Net::SSLeay::X509_subject_name_hash($root));
		if ($fp->{subject_hash_ca} eq $hash) {
		    warn "N $fp->{host}:$fp->{port} - subject_hash_ca as expected\n";
		} else {
		    warn "N $fp->{host}:$fp->{port} - subject_hash_ca changed from $fp->{subject_hash_ca} to $hash\n";
		    $fp->{subject_hash_ca} = $hash;
		    $changed++;
		}
	    }
	}
    }
    if ($changed) {
	require Data::Dumper;
	open(my $fh,'<',__FILE__) or die $!;
	my $pl = do { local $/; <$fh> };
	my $new = 'my $fingerprints= '.Data::Dumper->new([$fingerprints])->Terse(1)->Quotekeys(0)->Sortkeys(1)->Dump().";\n";
	$pl =~ s{^(# --- BEGIN-FINGERPRINTS ----\s*\n)(.*)^(# --- END-FINGERPRINTS ----\s*\n)}{$1$new$3}ms
	    or die "did not find BEGIN and END markers in ".__FILE__;
	open($fh,'>',__FILE__) or die $!;
	print $fh $pl;
	warn __FILE__." updated\n";
    }
}

$fingerprints;
