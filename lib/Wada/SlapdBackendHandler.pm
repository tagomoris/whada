package Wada::SlapdBackendHandler;

use strict;
use warnings;
use Carp;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub init {
    return 0;
}

sub search {
    croak "not implemented";
}

sub compare {
    croak "not implemented";
}

sub bind {
    my $this = shift;
    # you cannot bind with virtual entries.
    return 0;
}

sub modify {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
    return 0;
}

sub add {
    my $this = shift;
    # you cannot add entries to virtual entries.
    return 0;
}

sub modrdn {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
    return 0;
}

sub delete {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
}

sub config {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
    return 0;
}

1;
