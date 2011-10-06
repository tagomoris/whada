package Whada::Dictionary::File;

use strict;
use warnings;
use Carp;

use base qw/Whada::Dictionary/;

use Digest::SHA qw//;

sub new {
    my $this = shift;
    my $self = bless $this->SUPER::new(@_), $this;
    croak 'source file not exists:' . $self->{config}->{path} unless -f $self->{config}->{path};
    $self->{salt} = $self->{config}->{salt};
    $self->{map} = {};
    open my $fh, $self->{config}->{path};
    while (<$fh>) {
        chomp;
        my ($name, $hash) = split(/\s+/, $_);
        $self->{map}->{$name} = $hash;
    }
    close $fh;
    $self;
}

sub entry {
    my $self = shift;
    my $credential = shift;

    my $username = $credential->username();
    if ($self->{map}->{$username}) {
        return [['SAMACCOUNTNAME: ' . $username]];
    }
    return undef;
}

sub authenticate {
    my $self = shift;
    my $credential = shift;

    my $username = $credential->username();
    my $password = $credential->password();

    my $entry = $self->entry($credential);
    return undef unless $entry and scalar(@$entry) == 1;

    my $check_hash = Digest::SHA::sha1_hex($self->{salt} . $password);
    return $entry if $self->{map}->{$username} eq $check_hash;
    return undef;
}

1;
