package Whada::Dictionary::LDAP;

use strict;
use warnings;
use Carp;

use base qw/Whada::Dictionary/;

use Net::LDAP;

sub entry {
    my $self = shift;
    my $credential = shift;
    my $config = $self->{config};

    my $filter = ($config->{converter})->new({credential => $credential})->filter();

    my $ldap = Net::LDAP->new($config->{server});

    my $mesg = $ldap->bind($config->{binddn}, password => $config->{bindpassword});
    $mesg->code && croak "Dictionary entry[bind]: " . $mesg->error;

    $mesg = $ldap->search(base => $config->{base}, deref => 'never', filter => $filter);
    $mesg->code && croak "Dictionary entry[search]: " . $mesg->error;

    my $entry;
    my @entries = $mesg->entries;
    if (scalar(@entries) < 1) {
        $entry = undef;
    }
    else {
        $entry = \@entries;
    }
    $ldap->unbind;
    $ldap->disconnect;
    undef $ldap;

    return $entry;
}

sub authenticate {
    my $self = shift;
    my $credential = shift;
    my $entry = $self->entry($credential);

    return undef unless $entry and scalar(@$entry) == 1;
    my $dn = $entry->[0]->dn();

    my $config = $self->{config};
    my $ldap = Net::LDAP->new($config->{server});
    my $mesg = $ldap->bind($dn, password => $credential->password);
    $ldap->unbind;
    $ldap->disconnect;
    undef $ldap;

    return undef if $mesg->code != 0;
    return [$entry->[0]];
}

1;
