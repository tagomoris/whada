package Whada::PrivStore;

use strict;
use warnings;
use Carp;

use DBI;
use JSON;

use Log::Minimal;
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

sub storage {
    my $this = shift;
    my $host = $storage_conf->{host} || 'localhost';
    my $port = $storage_conf->{port} || 3306;
    my $username = $storage_conf->{username};
    my $password = $storage_conf->{password};
    my $dsn;
    if ($host eq 'localhost' and not $port and $username eq 'root' and $password eq '') {
        $dsn = "DBI:mysql:database=whadaadmin;host=localhost";
    }
    else {
        $dsn = "DBI:mysql:database=whadaadmin;host=$host;port=$port";
    }
    DBI->connect_cached($dsn, $username, $password)
        or die $DBI::errstr;
}

sub global_default_privilege {
    my $this = shift;
    my $result = ($this->storage())->selectrow_arrayref(
        "SELECT data FROM settings WHERE name='global_default_privilege'",
        {Slice => {}}
    );
    if (not $result or scalar(@{$result}) < 1) {
        return undef;
    }
    return $result->[0] eq 'allowed';
}

sub priv_data {
    my $this = shift;
    my $priv = shift;
    my $data = ($this->storage())->selectrow_hashref(
        "SELECT name,data FROM privs WHERE name=?",
        {Slice => {}},
        $priv
    );
    return {name => $priv} unless $data;
    try {
        return decode_json($data->{data});
    } catch {
        warnf 'failed to decode json:' . $data . ' about priv:' . $priv;
        return {name => $priv};
    };
}

sub priv_data_list {
    my $this = shift;
    my $list = ($this->storage())->selectall_arrayref(
        "SELECT name,data FROM privs",
        {Slice => {}},
    );
    my @results = ();
    foreach my $p (@{$list}) {
        try {
            push @results, decode_json($p->{data});
        } catch {
            warnf 'failed to decode json:' . $p->{data};
        };
    }
    return \@results;
}

sub save_priv_data {
    my $this = shift;
    my $data = shift;
    try {
        my $sth = ($this->storage())->prepare('INSERT INTO privs (name,data) values (?,?) ON DUPLICATE KEY UPDATE data=?');
        my $json = encode_json($data);
        $sth->execute($data->{name}, $json, $json);
    } catch {
        warnf 'failed to jsonize or insert priv data:' . ddf($data);
    };
}

sub drop_priv_data {
    my $this = shift;
    my $priv = shift;
    try {
        my $sth = ($this->storage())->prepare('DELETE FROM privs WHERE name=?');
        $sth->execute($priv);
        return 1;
    } catch {
        warnf 'failed to delete priv data:' . $priv;
        return 0;
    };
}

sub user_data {
    my $this = shift;
    my $username = shift;
    my $data = ($this->storage())->selectrow_hashref(
        "SELECT name,data FROM users WHERE name=?",
        {Slice => {}},
        $username
    );
    return {username => $username} unless $data;
    try {
        return decode_json($data->{data});
    } catch {
        warnf 'failed to decode json:' . $data->{data};
        return {username => $username};
    };
}

sub user_data_list {
    my $this = shift;
    my $list = ($this->storage())->selectall_arrayref(
        "SELECT name,data FROM users",
        {Slice => {}},
    );
    my @results = ();
    foreach my $p (@{$list}) {
        try {
            push @results, decode_json($p->{data});
        } catch {
            warnf 'failed to decode json:' . $p->{data};
        };
    }
    return \@results;
}

sub save_user_data {
    my $this = shift;
    my $data = shift;
    try {
        my $sth = ($this->storage())->prepare('INSERT INTO users (name,data) values (?,?) ON DUPLICATE KEY UPDATE data=?');
        my $json = encode_json($data);
        $sth->execute($data->{username}, $json, $json);
    } catch {
        warnf 'failed to jsonize or insert user data:' . ddf($data);
    };
}

sub drop_user_data {
    my $this = shift;
    my $username = shift;
    try {
        my $sth = ($this->storage())->prepare('DELETE FROM users WHERE name=?');
        $sth->execute($username);
        return 1;
    } catch {
        warnf 'failed to drop user:' . $username;
        return 0;
    };
}

sub priv_type {
    my $this = shift;
    return ($this->priv_data(shift))->{type};
}

sub check_priv_type {
    my $this = shift;
    my $type = shift;
    return scalar(grep {$type eq $_} @TYPES) == 1;
}

sub set_priv_type {
    my $this = shift;
    my ($priv, $type) = @_;
    unless ($this->check_priv_type($type)) {
        warnf 'invalid privilege type, ignored:' . $type;
        return;
    }
    my $data = $this->priv_data($priv);
    $data->{type} = $type;
    $this->save_priv_data($data);
}

sub limitation {
    my $this = shift;
    return ($this->user_data((shift)->username()))->{limited};
}

sub privileges {
    my $this = shift;
    return ($this->user_data((shift)->username()))->{privileges} || {}
}

sub allow_privileges {
    my $this = shift;
    my $credential = shift;
    my @privs = @_;
    my $data = $this->user_data($credential->username());
    $data->{privileges} ||= {};
    foreach my $p (@privs) {
        $data->{privileges}->{$p} = 'allowed';
    }
    $this->save_user_data($data);
}

sub deny_privileges {
    my $this = shift;
    my $credential = shift;
    my @privs = @_;
    my $data = $this->user_data($credential->username());
    $data->{privileges} ||= {};
    foreach my $p (@privs) {
        $data->{privileges}->{$p} = 'denied';
    }
    $this->save_user_data($data);
}

sub check {
    my $this = shift;
    my $credential = shift;
    my $priv = $credential->privilege;
    my $type = $this->priv_type($priv);
    my $limit = $this->limitation($credential);
    my $privs = $this->privileges($credential);

    unless (defined $type) {
        warnf 'undefined privilege:' . $priv;
        return undef;
    }
    if ($limit) {
        return 0 if ($type eq 'always_deny');
        return 1 if (exists($privs->{$priv}) and $privs->{$priv} eq 'allowed');
        return 0;
    }

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
