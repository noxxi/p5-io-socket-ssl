# to update fingerprints in this file:
# perl -e 'do q[t/external/fingerprint.pl]; update_fingerprints()'

use strict;
use warnings;
use IO::Socket::SSL;

# --- BEGIN-FINGERPRINTS ----
my $fingerprints= [
  {
    _ => 'this should give us OCSP stapling',
    fingerprint => 'sha1$cc7084a0fb728b432fd78ae52da4a1980c81a6cf',
    host => 'www.chksum.de',
    ocsp => {
	      staple => 1
	    },
    port => 443
  },
  {
    _ => 'no OCSP stapling',
    fingerprint => 'sha1$ad737048455485d8c817b7d0f7403553a7b9f65b',
    host => 'www.spiegel.de',
    ocsp => {
	      staple => 0
	    },
    port => 443,
    subject_hash_ca => '2c543cd1'
  },
  {
    _ => 'this is revoked',
    fingerprint => 'sha1$f9e8b1854e627c2f261b92b6de4a9bb0b139dcc3',
    host => 'revoked.grc.com',
    ocsp => {
	      revoked => 1
	    },
    port => 443
  },
  {
    fingerprint => 'sha1$dc0866cdf51594fd85ccf249d507164552828ad2',
    host => 'www.yahoo.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$cda53778d01ff728fe90fe0399b17586f1aef0bf',
    host => 'www.comdirect.de',
    port => 443,
    subject_hash_ca => '02265526'
  },
  {
    fingerprint => 'sha1$27d647fd859bf824d9f537a09aa98e4923fb6942',
    host => 'meine.deutsche-bank.de',
    port => 443,
    subject_hash_ca => 'c01cdfa2'
  },
  {
    fingerprint => 'sha1$682d7ff1b13e095bf5daaa632ece51f4df5bb155',
    host => 'www.twitter.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$936f912bafad216fa515256e572cdc35a1451aa5',
    host => 'www.facebook.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$3b9e5cc01313b6f86709646f1be4a057ed75bcc9',
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
	    SSL_verify_callback => sub {
		my ($cert,$depth) = @_[4,5];
		$root ||= $cert;
		return 1;
	    }
	)) {
	    warn "E $fp->{host}:$fp->{port} - SSL handshake failed: $SSL_ERROR\n";
	} else {
	    my $sha1 = $cl->get_fingerprint('sha1');
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
