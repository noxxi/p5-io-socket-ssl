# Copyright Steffen Ullrich 2023
# License: public domain (no restrictions)

use strict;
use warnings;
use Net::Inspect;
use Net::Inspect::L2::Pcap;
use Net::Inspect::L3::IP;
use Net::Inspect::L4::TCP;
use Net::Pcap;
use lib '.';
use JAX qw(ja3 ja4 ja3s);

for my $file (@ARGV) {
    my $err;
    my $pcap = pcap_open_offline($file,\$err);
    $pcap or die $err;

    my $tcp = Net::Inspect::L4::TCP->new(Analyzer->new(
	1 => \&fp_client,
	2 => \&fp_server,
    ));
    my $raw = Net::Inspect::L3::IP->new([$tcp]);
    my $pc  = Net::Inspect::L2::Pcap->new($pcap,$raw);

    my $time;
    pcap_loop($pcap,-1,sub {
	my (undef,$hdr,$data) = @_;
	if ( ! $time || $hdr->{tv_sec}-$time>10 ) {
	    #$tcp->expire($time = $hdr->{tv_sec});
	}
	return $pc->pktin($data,$hdr);
    },undef);
}

sub fp_client {
    my ($chello,$analyzer) = @_;
    _dump($analyzer);
    print "JA3       ".ja3($chello)."\n";
    print "JA3 raw   ".ja3($chello,1)."\n";
    print "JA3N      ".ja3($chello,0,1)."\n";
    print "JA3N raw  ".ja3($chello,1,1)."\n";
    print "JA4       ".ja4($chello)."\n";
    print "JA4 raw   ".ja4($chello,1)."\n";
    print "JA4_o     ".ja4($chello,0,0)."\n";
    print "JA4_o raw ".ja4($chello,1,0)."\n";
    print "------\n";
}

sub fp_server {
    my ($shello,$analyzer) = @_;
    _dump($analyzer);
    print "JA3S      ".ja3s($shello)."\n";
    print "JA3S  raw ".ja3s($shello,1)."\n";
    print "JA3SN     ".ja3s($shello,0,1)."\n";
    print "JA3SN raw ".ja3s($shello,1,1)."\n";
    print "------\n";
}

sub _dump {
    my $m = shift->{meta};
    print "$m->{saddr}:$m->{sport} - $m->{daddr}:$m->{dport}\n";
}

1;

package Analyzer;
use base 'Net::Inspect::Connection';
use fields qw(buf meta recmap);

sub new {
    my ($class,%recmap) = @_;
    if (ref($class)) {
	my $self = fields::new(ref($class));
	$self->{recmap} = $class->{recmap};
	$self->{buf} = [ '','' ];
	return $self;
    }
    my $self = fields::new($class);
    $self->{recmap} = \%recmap;
    return $self;
}

sub syn { 1 }
sub fatal { warn "@_\n" }

sub new_connection {
    my ($self,$meta) = @_;
    $self = $self->new;
    $self->{meta} = $meta;
    return $self;
}

sub in {
    my ($self,$dir,$data,$eof) = @_;
    return if $eof or $data eq '';
    my $buf = \$self->{buf}[$dir];

    $$buf .= $data;
    while (1) {
	if ($$buf =~m{\x16\x03[\x00-\x03](..)}sg) {
	    # remove everything in front
	    substr($$buf,0,pos($$buf)-5,'') if pos($$buf)>5;
	    my $len = unpack("n",$1);
	    if ($len+5 > length($$buf)) {
		# need more
		last
	    }
	    # extract inner handshake protocol
	    (my $rec, $$buf) = unpack("x3 n/a a*", $$buf);
	    (my $type, $rec) = unpack("c x3 a*", $rec);
	    my $fpsub = $self->{recmap}{$type} or next;
	    $fpsub->($rec,$self);
	} else {
	    # does not look like TLS, remove unneeded part
	    substr($$buf,0, length($$buf)-3, '') if length($$buf)>3;
	    last;
	}
    }
    return length($data);
}
