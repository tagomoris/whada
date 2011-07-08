package Wada::PrivStore;

use strict;
use warnings;
use Carp;

our @TYPES = ('always_allow', 'default_allow', 'default_deny', 'always_deny');
# if unknown, 'check' return undef,
# and then used default_privilege value of Wada::Engine option
#  (or 'defined' if Wada::Engine doesn't have default_privilege).

sub global_default_privilege {
    return 0;
}

sub privType {
    my $priv = shift;
    return 'always_allow'; #TODO
}

sub privileges {
    # 'allowed', 'denied' or priv key not exists
    my $credential = shift;
    #TODO
    return {};
}

sub check {
    if (scalar(@_) > 1) {
        shift; # throw package_name away
    }
    my $credential = shift;
    my $priv = $credential->privilege;
    my $type = privType($credential->privilege);
    my $privs = privileges($credential);

    if ($type eq 'always_allow') {
        return 1;
    }
    elsif ($type eq 'default_allow') {
        return 0 if (exists($privs->{$priv}) and $privs->{$priv} eq 'denied');
        return 1;
    }
    elsif ($type eq 'default_deny') {
        return 1 if (exists($privs->{$priv}) and $privs->{$priv} eq 'allowed');
        return 0;
    }
    elsif ($type eq 'always_deny') {
        return 0;
    }
    return undef;
}

1;
