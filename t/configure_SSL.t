#!perl

use strict;
use warnings;

use Socket ();
use IO::Socket::SSL;

use Test::More tests => 11;

do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

my $PING_PONG_MAX = 20;

my %server_options = (
    SSL_server      => 1,
    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
    SSL_cert_file   => "certs/server-cert.pem",
    SSL_key_file    => 'certs/server-key.pem',
);

my $main_process_id = $$;

$SIG{'USR1'} = sub { };    # do nothing
my $spammer_pid = fork();
die q{Failed to fork} unless defined $spammer_pid;
start_spammer($main_process_id) unless $spammer_pid;

my ($kid_pid, $server_socket);

foreach my $num ( 1 .. 10 ) {
   alarm 2;
    ( $kid_pid, $server_socket ) = set_up_socket_for_ping_pong();

    waitpid $kid_pid, 0;
    undef $kid_pid;
    undef $server_socket;

    pass("ping pong $num");
}

kill 9, $spammer_pid;
waitpid $spammer_pid, 0;

pass("Done");
exit;

sub start_spammer {
    my $parent_pid = shift;

    for (1..20) {    # let's spam it
        kill 'USR1', $parent_pid;
        select( undef, undef, undef, 0.01 );
    }

    exit(0);
}

sub set_up_socket_for_ping_pong {
    socketpair(
        my $client_socket,
        my $server_socket,
        &Socket::AF_UNIX,
        &Socket::SOCK_STREAM,
        &Socket::PF_UNSPEC
    );

    my $pid = fork;
    die("Can't fork") unless defined $pid;

    ##### Child process.
    if ( $pid == 0 ) {
        close $server_socket;
        $client_socket->blocking(0);
        IO::Socket::SSL->start_SSL( $client_socket, SSL_verify_mode => 0 )
          or die "CanÕt upgrade child to SSL: $IO::Socket::SSL::SSL_ERROR";

        _ping_pong( $client_socket, $client_socket );
        exit;
    }

    ##### Parent process
    $server_socket->blocking(0);

    #diag sprintf( "CHILD ($pid) = %s, PARENT ($$) = %s", fileno($client_socket), fileno($server_socket) );
    my $started_ssl = 0;
    while ( !$started_ssl ) {
        if ( IO::Socket::SSL->start_SSL( $server_socket, %server_options ) ) {
            $started_ssl = 1;
        }
        else {
            next if $IO::Socket::SSL::SSL_ERROR == IO::Socket::SSL::SSL_WANT_READ;
            die "Cannot upgrade parent to SSL: $IO::Socket::SSL::SSL_ERROR";
        }
    }

    close $client_socket;

    return ( $pid, $server_socket );
}

sub _ping_pong {
    my ( $in_fh, $out_fh ) = @_;

    foreach my $num ( 1 .. $PING_PONG_MAX ) {
        syswrite( $out_fh, "$num\n" );
    }

    undef($in_fh);
    undef($out_fh);

    return;
}
