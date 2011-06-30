package Wada::Engine;

use strict;
use warnings;
use Carp;

use Wada::Logger;
use Wada::PrivStore;

# check authorized or not, but not check authenticated or not.
sub authorize {
    if (scalar(@_) > 1) {
        shift; # throw package_name away
    }
    my $opts = shift;
    my $credential = $opts->{credential};
    my $dictionary = $opts->{dictionary};
    my $logger = $opts->{logger};
    croak 'credential not found' unless $credential;
    croak 'dictionary not found' unless $dictionary;
    croak 'failed to init logger' unless $logger;

    return drive($credential, $logger, $opts->{default_priv}, 0, sub {
                     return $dictionary->entry(shift);
                 });
}

# check authorized or not, and also check authenticated or not.
sub authenticate {
    if (scalar(@_) > 1) {
        shift; # throw package_name away
    }
    my $opts = shift;
    my $credential = $opts->{credential};
    my $dictionary = $opts->{dictionary};
    my $logger = $opts->{logger};
    croak 'credential not found' unless $credential;
    croak 'dictionary not found' unless $dictionary;
    croak 'failed to init logger' unless $logger;

    return drive($credential, $logger, $opts->{default_priv}, 1, sub {
                     return $dictionary->authenticate(shift);
                 });
}

sub drive {
    my ($credential, $logger, $default_priv, $with_authentication, $sub) = @_;

    my $authorized_check = Wada::PrivStore->check($credential);
    my $authorized = 0;
    my $entry;
    if (defined($authorized_check) and $authorized_check) {
        $authorized = 1;
        $entry = $sub->($credential);
    }
    elsif (defined(authorized_check)) {
        # not authorized
        $entry = undef;
    }
    # undef of authorized_check means unknown privilege label
    elsif ($default_priv eq 'allowed') {
        $authorized = 1;
        $entry = $sub->($credential);
    }
    elsif ($default_priv eq 'denied') {
        # not authorized
        $entry = undef;
    }
    elsif (Wada::PrivStore->global_default_privilege) {
        $authorized = 1;
        $entry = $sub->($credential);
    }
    else {
        # not authorized
        $entry = undef;
    }

    if ($authorized and $entry and $with_authentication) {
        $logger->logging($credential, 'successed');
    }
    if ($authorized and $entry) {
        $logger->logging($credential, 'authorized (without password verification)');
    }
    elsif ($authorized) {
        $logger->logging($credential, 'authentication failed');
    }
    else {
        $logger->logging($credential, 'not authorized');
    }
    return $entry;
}

1;

