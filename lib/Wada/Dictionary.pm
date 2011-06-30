package Wada::Dictionary;

use strict;
use warnings;
use Carp;

sub entry {
    # 1. get model, and convert model to dictionary-native-data (ex: filter on LDAP)
    # 2. get and return dictionary-entry searched by 1. data, with configured fixed user/pass
    croak 'not implemented';
}

sub authenticate {
    # 1. get model, and convert model to dictionary-native-data (ex: filter on LDAP)
    # 2. check authentication with passed user/pass in 1. data
    # 3. get and return dictionary-entry searched by 1. data with authenticated account
    croak 'not implemented';
}

1;
