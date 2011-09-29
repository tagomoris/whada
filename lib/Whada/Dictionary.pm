package Whada::Dictionary;

use strict;
use warnings;
use Carp;

sub new {
    my $this = shift;
    my $converter = shift;
    my $conf = shift || {};
    return bless {converter => $converter, config => $conf}, $this;
}

sub entry {
    # 1. get credential, and convert credential to dictionary-native-data (ex: filter on LDAP)
    # 2. get and return dictionary-entry searched by 1. data, with configured fixed user/pass
    # returns ldap entry string (success), or undef (not found)
    croak 'not implemented';
}

sub authenticate {
    # 1. get credential, and convert credential to dictionary-native-data (ex: filter on LDAP)
    # 2. check authentication with passed user/pass in 1. data
    # 3. get and return dictionary-entry searched by 1. data with authenticated account
    # returns ldap entry string (success) or undef (access denied)
    croak 'not implemented';
}

1;
