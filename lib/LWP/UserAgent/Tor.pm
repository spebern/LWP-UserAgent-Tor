package LWP::UserAgent::Tor;

use 5.010;
use strict;
use warnings;
no warnings 'exec';
use Carp;
use LWP::UserAgent;
use IO::Socket::INET;
use LWP::Protocol::socks;
use Net::EmptyPort qw(empty_port);

use base 'LWP::UserAgent';

our $VERSION = '0.03';

sub new {
    my ($class, %args) = @_;

    my $tor_control_port = delete( $args{tor_control_port} ) // empty_port();
    my $tor_port         = delete( $args{tor_port} )         // empty_port($tor_control_port);
    my $tor_ip           = delete( $args{tor_ip} )           // 'localhost';
    my $tor_cfg          = delete( $args{tor_cfg} );

    my $self = $class->SUPER::new(%args);
    $self->{_tor_pid}    = _start_tor_proc($tor_ip, $tor_port, $tor_control_port, $tor_cfg);
    $self->{_tor_socket} = IO::Socket::INET->new(
        PeerAddr => $tor_ip,
        PeerPort => $tor_control_port,
    ) // croak 'could not connect to tor';

    $self->proxy( [ 'http', 'https' ], "socks://$tor_ip:$tor_port" );

    return bless $self, $class;
}

sub DESTROY {
    my ($self) = @_;

    my $tor_pid = $self->{_tor_pid};
    kill 9, $tor_pid if defined $tor_pid;
    $self->SUPER::DESTROY if $self->can('SUPER::DESTROY');

    return;
}

sub _start_tor_proc {
    my ($ip, $port, $control_port, $cfg) = @_;

    my $tor_cmd = "tor --ControlListenaddress $ip:$control_port --ControlPort auto --SocksPort $port --quiet";
    if (defined $cfg){
        croak 'tor config file does not exist' unless -e $cfg;
        $tor_cmd .= " -f $cfg";
    }

    my $pid = fork() // die "fork() failed: $!";
    if ($pid == 0) {
        exec $tor_cmd;
        croak 'error running tor (probably not installed?)';
    }

    # starting tor...
    sleep 1;

    return $pid;
}


sub rotate_ip {
    my ($self) = @_;

    my $socket = $self->{_tor_socket};
    my $answer = q{};

    $socket->send("AUTHENTICATE\n");
    $socket->recv($answer, 1024);
    return 0 unless $answer eq "250 OK\r\n";

    $socket->send("SIGNAL NEWNYM\n");
    $socket->recv($answer, 1024);
    return 0 unless $answer eq "250 OK\r\n";

    return 1;
}

1;

__END__

=pod
 
=encoding UTF-8
 
=head1 NAME

LWP::UserAgent::Tor - rotate your ips

=head1 VERSION

version 0.01

=head1 SYNOPSIS
 
  use LWP::UserAgent::Tor;

  my $ua = LWP::UserAgent::Tor->new(
      tor_control_port => 9051,            # empty port on default range(49152 .. 65535)
      tor_port         => 9050,            # empty port on default range(49152 .. 65535)
      tor_ip           => '127.0.0.1',     # localhost on default
      tor_config       => 'path/to/torrc', # tor default config path
  );

  if ($ua->rotate_ip) {
      say 'got another ip';
  }
  else {
      say 'Try again?';
  }

=head1 DESCRIPTION

Inherits directly form LWP::UserAgent. Launches tor proc in background
and connects to it via socket. Every method call of C<rotate_ip> will send
a request to change the exit node and return 1 on sucess.

=head1 METHODS

=head2 rotate_ip

  $ua->rotate_ip;

Try to get another exit node via tor.
Returns 1 for success and 0 for failure.

=head1 ACKNOWLEDGEMENTS

Inspired by a script of ac0v overcoming some limitations (no more!) of web scraping...

=head1 LICENSE

This is released under the Artistic License.

=head1 AUTHOR

spebern <bernhard@specht.net>

=cut

