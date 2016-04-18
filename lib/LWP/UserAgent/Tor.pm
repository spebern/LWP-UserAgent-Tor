package LWP::UserAgent::Tor;

use strict;
use warnings;
use Carp;
use IO::Socket::Telnet;
use LWP::Protocol::socks;

use parent 'LWP::UserAgent';

our $VERSION = '0.01';

sub new {
    my ($class, %args) = @_;

    my $tor_control_port = delete( $args{tor_control_port} ) // 9051;
    my $tor_port         = delete( $args{tor_port} )         // 9050;
    my $tor_ip           = delete( $args{tor_ip} )           // '127.0.0.1';

    my $tor_pid = _start_tor_proc($tor_ip, $tor_port, $tor_control_port);

    my $self = $class->SUPER::new(%args);
    $self->{_tor_pid}     = $tor_pid;
    $self->{_tor_socket}  = IO::Socket::Telnet->new(
        PeerAddr => $tor_ip,
        PeerPort => $tor_control_port,
    );

    $self->proxy(
        [ 'http', 'https' ], "socks://$tor_ip:$tor_port"
    );

    return bless($self, $class);
}

sub DESTROY {
    my ($self) = @_;

    kill 9, $self->{_tor_pid};
    $self->SUPER::DESTROY if $self->can('SUPER::DESTROY');

    return;
}

sub _start_tor_proc {
    my ($ip, $port, $control_port) = @_;

    my $pid = fork() // die "fork() failed: $!";
    if ($pid == 0) {
        exec "tor --ControlListenaddress $ip:$control_port --ControlPort auto --SocksPort $port --quiet";
    }

    sleep 1;

    return $pid;
}


sub rotate_ip {
    my ($self) = @_;

    my $socket      = $self->{_tor_socket};

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


