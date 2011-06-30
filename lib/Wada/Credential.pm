package Wada::Credential;

use strict;
use warnings;
use Carp;

sub new {
    my $this = shift;
    my $args = shift;
    my $self = {};
    if ($args->{domain}) {
        $self->{domain} = $args->{domain};
    }
    if ($args->{username}) {
        $self->{username} = $args->{username};
    }
    if ($args->{password}) {
        $self->{password} = $args->{password};
    }
    if ($args->{mail}) {
        $self->{mail} = $args->{mail};
    }
    if ($args->{privilege}) { #TODO privileges ?
        $self->{privilage} = $args->{privilege};
    }
    return bless $self, $this;
}

sub ident {
    my $self = shift;
    return $self->username || $self->mail;
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

#TODO privilege or privileges ?
sub privilege {
    return shift->{privilege};
}

sub logformat {
    my $self = shift;
    return "[" . $self->{privilege} . "] " . $self->ident;
}

1;
