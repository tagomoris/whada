package Whada::Converter;

use strict;
use warnings;
use Carp;

use Whada::Credential;

my $CONVERTER_GLOBAL_DEFAULT = {};

sub set_global_default {
    shift;
    $CONVERTER_GLOBAL_DEFAULT = shift;
}

sub new {
    my $this = shift;
    my $args = shift;
    croak "invalid argument: only single key-value pair is allowed" if scalar(keys(%$args)) != 1;
    my $self = {args => $args, conf => $CONVERTER_GLOBAL_DEFAULT};
    return bless $self, $this;
}

sub conf { (shift)->{conf}; }

# in Subclass as subclass of Whada::Converter
#   sub credential_from_filter {};
#   sub filter_from_credential {};
# This converter is for SlapdBackendHandler, and LDAP another data souce.
# you can call
#   Subclass->new(filter => $filterString)->credential();
#   Subclass->new(credential => $credential)->filter();
#
# in Subclass2 as subclass of Whada::Converter
#   sub credential_from_oauthobj {};
#   sub mysqlqueryparams_from_credential {};
# This converter is for OAuthHandler, and MySQL user-password database.
# you can call
#   Subclass->new(oauthobj => obj)->credential();
#   subclass->new(credential => $credential)->mysqlqueryparams();

sub credential {
    my $self = shift;
    my $material = (keys(%{$self->{args}}))[0];
    croak "invalid material for credential: $material" unless $self->{args}->{$material};
    my $method = 'credential_from_' . $material;
    croak "undefined method: $method" unless $self->can($method);
    return $self->$method($self->{args}->{$material});
}

sub DESTROY {
}

sub AUTOLOAD {
    my $this = $_[0];
    my $called = our $AUTOLOAD;

    $called =~ s/.*:://o;
    $called =~ s/^u_?//o;
    my $material = (keys(%{$this->{args}}))[0];
    croak "invalid material for $called: $material" unless $this->{args}->{$material};
    my $method = $called . '_from_' . $material;
    croak "undefined method: $method" unless $this->can($method);

    no strict 'refs';
    *{$AUTOLOAD} = sub {
        my $self = shift;
        return $self->$method($self->{args}->{$material});
    };
    goto &$AUTOLOAD;
}

1;
