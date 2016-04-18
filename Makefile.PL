use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'LWP::UserAgent::Tor',
    AUTHOR           => q{spebern <bernhard@specht.net>},
    VERSION_FROM     => 'lib/LWP/UserAgent/Tor.pm',
    ABSTRACT_FROM    => 'lib/LWP/UserAgent/Tor.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        LWP::UserAgent       => 0,
        IO::Socket::Telnet   => 0,
        LWP::Protocol::socks => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'LWP-UserAgent-Tor-*' },
);
