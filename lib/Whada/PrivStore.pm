package Whada::PrivStore;

use strict;
use warnings;
use Carp;

use Cache::KyotoTycoon;
use JSON;

use Try::Tiny;

our @TYPES = ('always_allow', 'default_allow', 'default_deny', 'always_deny');
# if unknown, 'check' return undef,
# and then used default_privilege value of Whada::Engine option
#  (or 'denied' if Whada::Engine doesn't have default_privilege).

my $storage_conf = {};
sub set_storage_configuration {
    my $this = shift;
    my ($attr, $value) = @_;
    $storage_conf->{$attr} = $value;
}

my $storage_connection; # connection cache
sub storage {
    my $self = shift;
    return $storage_connection if $storage_connection;
    my $host = $storage_conf->{host} || '127.0.0.1';
    my $port = $storage_conf->{port} || 1978;
    $storage_connection = Cache::KyotoTycoon->new(host => $host, port => $port);
    $storage_connection;
}

sub global_default_privilege {
    my $p = (storage())->get('global_default_privilege');
    return $p eq 'allowed';
}

sub privType {
    my $priv = shift;
    my $data = (storage())->get('priv:' . $priv);
    my $p;
    try {
        $p = decode_json($data);
    } catch {
        return global_default_privilege();
    };
    return ($p->{priv_type} || global_default_privilege());
}

sub privileges {
    my $credential = shift;
    my $data = (storage())->get('user:' . $credential->username());
    my $u;
    try {
        $u = decode_json($data);
    } catch {
        return {};
    }
    return ($u->{privileges} || {});
}

sub check {
    if (scalar(@_) > 1) {
        shift; # throw package_name away
    }
    my $credential = shift;
    my $priv = $credential->privilege;
    my $type = privType($priv);
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
