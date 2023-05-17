# to update fingerprints in this file:
# perl -e 'do q[./t/external/fingerprint.pl]; update_fingerprints()'

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
    fingerprint => 'sha1$pub$7bb3ccee47202aaa3ff54385d1e16041607c2717',
    host => 'www.bild.de',
    ocsp => {
              staple => 0
            },
    port => 443,
    subject_hash_ca => '3513523f'
  },
  {
    _ => 'this is revoked',
    fingerprint => 'sha1$pub$f0f0c49b8a04a2dd2110e10f7806c97d87d0b26f',
    host => 'revoked.grc.com',
    ocsp => {
              revoked => 1
            },
    port => 443
  },
  {
    fingerprint => 'sha1$pub$8420580d25d48cbe657b44d44ffb3208c809d853',
    host => 'www.yahoo.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$ca8114a3303ff688f63c70ae2e605d39f6f654cb',
    host => 'www.comdirect.de',
    port => 443,
    subject_hash_ca => '062cdee6'
  },
  {
    fingerprint => 'sha1$pub$26907a3f3088cf57264f7a0f083767e400ea871e',
    host => 'meine.deutsche-bank.de',
    port => 443,
    subject_hash_ca => '607986c7'
  },
  {
    fingerprint => 'sha1$pub$916746dac08bb07342b3e5b76a80d108b6c3205b',
    host => 'www.twitter.com',
    port => 443,
    subject_hash_ca => '3513523f'
  },
  {
    fingerprint => 'sha1$pub$dd05d516982dc8d869fcb3269f323232eeaf2204',
    host => 'www.facebook.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$6ad05c9dd77463152389f755cb6a81c41c33c987',
    host => 'www.live.com',
    port => 443,
    subject_hash_ca => '3513523f'
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
