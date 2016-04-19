use strict;
use warnings;
use Test::More tests => 10;
use Test::Exception;
use LWP::UserAgent::Tor;

{ # default values
    my $ua = LWP::UserAgent::Tor->new;

    isa_ok $ua, 'LWP::UserAgent::Tor', 'Created object (default args)';

    like $ua->{_tor_pid}, qr/\d*[1-9]/, 'Started tor proc (default args)';

    isa_ok $ua->{_tor_socket}, 'IO::Socket::INET', 'Connected to tor (default args)';

    # 5 tries
    my $suc = 0;
    for (0 .. 4) {
        $suc = $ua->rotate_ip;
        last if $suc;
    }

    ok $suc, 'Changed ip (default args)';
}

{
    my $ua = LWP::UserAgent::Tor->new(
        tor_control_port => 9050,
        tor_port         => 9051,
        tor_ip           => 'localhost',
        tor_cfg          => 't/torrc',
    );

    isa_ok $ua, 'LWP::UserAgent::Tor', 'Created object';

    like $ua->{_tor_pid}, qr/\d*[1-9]/, 'Started tor proc';

    isa_ok $ua->{_tor_socket}, 'IO::Socket::INET', 'Connected to tor';

    # 5 tries
    my $suc = 0;
    for (0 .. 4) {
        $suc = $ua->rotate_ip;
        last if $suc;
    }

    ok $suc, 'Chaned ip';
}

# exceptions
throws_ok {
    LWP::UserAgent::Tor->new(
        tor_control_port => 9050,
        tor_port         => 9050,
    );
} qr/could not connect to tor/, 'Die if socket cannot connect to tor';

throws_ok {
    LWP::UserAgent::Tor->new(
        tor_control_port => 9051,
        tor_port         => 9050,
        tor_cfg          => 'not_existing',
    );
} qr/tor config file does not exist/, "Die if tor cfg doesn't exist";

