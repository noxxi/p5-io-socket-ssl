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
    fingerprint => 'sha1$pub$8facee0f1cd627f8f2eff3caae6ad5579ca1b01d',
    host => 'www.bild.de',
    ocsp => {
              staple => 0
            },
    port => 443,
    subject_hash_ca => '3513523f'
  },
  {
    _ => 'this is revoked',
    fingerprint => 'sha1$pub$31b4b89651e35cb09606f445172d3e7c5642ed74',
    host => 'revoked.grc.com',
    ocsp => {
              revoked => 1
            },
    port => 443
  },
  {
    fingerprint => 'sha1$pub$1ada705dc522af9da86c6e0788c1a2525c07c7d3',
    host => 'www.yahoo.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$823f1729628d4fd8b7fd3f37488e6f19c5b15178',
    host => 'www.comdirect.de',
    port => 443,
    subject_hash_ca => '062cdee6'
  },
  {
    fingerprint => 'sha1$pub$19d4c556a1cccbe84270c474346e9ad737d1b1b2',
    host => 'meine.deutsche-bank.de',
    port => 443,
    subject_hash_ca => '607986c7'
  },
  {
    fingerprint => 'sha1$pub$59b067366473a080210fcab6e17a5d4486d1948e',
    host => 'www.twitter.com',
    port => 443,
    subject_hash_ca => '607986c7'
  },
  {
    fingerprint => 'sha1$pub$73a457e8b59c271cee98a79a3a9e1dc4d1b6126a',
    host => 'www.facebook.com',
    port => 443,
    subject_hash_ca => '244b5494'
  },
  {
    fingerprint => 'sha1$pub$8fa5e67c40659e2afa5ed08c7a29f6e62d58d01c',
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
