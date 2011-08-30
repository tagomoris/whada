package Whada::Credential;

use strict;
use warnings;
use Carp;

sub new {
    my $this = shift;
    my $args = shift || {};
    my $self = {};

    if ($args->{username}) {
        $self->{username} = $args->{username};
    }
    if ($args->{password}) {
        $self->{password} = $args->{password};
    }
    if ($args->{mail}) {
        $self->{mail} = $args->{mail};
    }
    if ($args->{privilege}) {
        $self->{privilege} = $args->{privilege};
    }
    return bless $self, $this;
}

sub ident {
    my $self = shift;
    return $self->username() || $self->mail();
}

sub username {
    return shift->{username};
}

sub password {
    return shift->{password};
}

sub mail {
    return shift->{mail};
}

sub privilege {
    return shift->{privilege};
}

sub logformat {
    my $self = shift;
    return "[" . ($self->{privilege} || 'NONE') . "] " . $self->ident();
}

1;
