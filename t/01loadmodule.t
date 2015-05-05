use strict;
use warnings;
no warnings 'once';
use Test::More;

plan tests => 3;

ok( eval { require IO::Socket::SSL },"loaded");

diag( sprintf( "openssl version=0x%0x", Net::SSLeay::OPENSSL_VERSION_NUMBER()));
diag( sprintf( "Net::SSLeay version=%s", $Net::SSLeay::VERSION));
diag( sprintf( "parent %s version=%s", $_, $_->VERSION))
    for (@IO::Socket::SSL::ISA);

IO::Socket::SSL->import(':debug1');
is( $IO::Socket::SSL::DEBUG,1, "IO::Socket::SSL::DEBUG 1");
is( $Net::SSLeay::trace,1, "Net::SSLeay::trace 1");

