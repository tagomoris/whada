package Whada::Converter::LDAP;

use strict;
use warnings;
use Carp;

use Net::LDAP::Filter;

use base qw/Whada::Converter/;

use Whada::Credential;

my $ACCOUNT_FILTER_ATTRIBUTE = 'sAMAccountName';
my $ACCOUNT_FILTER_VALUE = sub {
    my $credential = shift;
    $credential->username();
};
my $MAIL_ADDR_DOMAIN = '@example.com';

sub set_ldap_specifications {
    my $conf = {@_};
    return unless $conf;

    $ACCOUNT_FILTER_ATTRIBUTE = $conf->{filter}->{attribute} if ($conf->{filter} and $conf->{filter}->{attribute});
    $ACCOUNT_FILTER_VALUE = $conf->{filter}->{value} if ($conf->{filter} and $conf->{filter}->{value});
    $MAIL_ADDR_DOMAIN = $conf->{mail}->{domain} if ($conf->{mail} and $conf->{mail}->{domain});
}

# This method accepts only ldapquery,
#   hash reference such as {base => 'ou=base,dc=of,dc=ldap,dc=backend', filter => '(&(objectclass=*)(uid=tagomoris))'}
#   filter:
#     - single equalityMatch: (uid='foo')
#     - single '&' subtree with equalityMatch Array: (&(objectclass='*')(uid='bar')(privilege='admin'))
sub credential_from_ldapquery {
    my ($self, $ldapquery) = @_;
    my $args = {};

    my $base = $ldapquery->{base};
    if ($base and scalar(grep {/^ou=/i} split(',', $base)) > 0) {
        $args->{privilege} = (map {/^ou=(.*)/; $1} grep {/^ou=/i} split(',', $base))[0];
    }

    croak "filter doesn't exist" unless $ldapquery->{filter};

    my @matchers = ();
    # delete undefined attribute mark such as (?unknownattribute=HOGE)
    $ldapquery->{filter} =~ s/\(\?/(/g;

    my $filter = Net::LDAP::Filter->new($ldapquery->{filter});
    if ($filter->{equalityMatch}) {
        my $obj = $filter->{equalityMatch};
        push @matchers, [$obj->{attributeDesc}, $obj->{assertionValue}];
    }
    elsif ($filter->{and}) {
        foreach my $objx (@{$filter->{and}}) {
            next unless $objx->{equalityMatch};
            my $obj = $objx->{equalityMatch};
            push @matchers, [$obj->{attributeDesc}, $obj->{assertionValue}];
        }
    }
    else {
        croak "invalid filter constructure...";
    }

    foreach my $pair (@matchers) {
        my ($attr, $val) = @{$pair};
        if ($attr =~ /\Apriv(ilege)?\Z/i) {
            $args->{privilege} = $val;
        }
        elsif ($attr =~ /\Auid\Z/i or $attr =~ /\Auser(name)?\Z/i or $attr =~ /\AsAMAccountName\Z/i) {
            $args->{username} = $val;
        }
        elsif ($attr =~ /\Amail(address)?\Z/i) {
            $args->{mail} = $val;
        }
        elsif ($attr =~ /\Aaccount(name)?\Z/i) {
            if (index($val, '@') > 0) {
                # at-mark of head of value is ignored.
                $args->{mail} ||= $val;
            }
            else {
                $args->{username} ||= $val;
            }
        }
    }
    if ($args->{username} and not $args->{mail}) {
        $args->{mail} = $args->{username} . $MAIL_ADDR_DOMAIN;
    }
    elsif ($args->{mail} and not $args->{username}) {
        ($args->{username}) = ($args->{mail} =~ /\A([^@]+)@/)
    }

    return Whada::Credential->new($args);
}

sub filter_from_credential {
    my ($self, $credential) = @_;
    croak "credential doesn't exists" unless $credential;
    return '(' . $ACCOUNT_FILTER_ATTRIBUTE . '=' . $ACCOUNT_FILTER_VALUE->($credential) . ')';
}

1;
