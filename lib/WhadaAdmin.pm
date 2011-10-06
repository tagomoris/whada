package WhadaAdmin;

use strict;
use warnings;
use utf8;

use Try::Tiny;

use DBI;
use DBD::mysql;
use HTTP::Session;
use HTTP::Session::Store::DBI;
use HTTP::Session::State::Cookie;

use JSON;

use Kossy;
use Log::Minimal;

use WhadaAdmin::Config;

use Whada::Engine;
use Whada::PrivStore;
use Whada::Credential;

# for debug...
use Data::Dumper;

our $VERSION = 0.01;

sub config {
    my $self = shift;
    return $self->{_config} if $self->{_config};
    $self->{_config} = WhadaAdmin::Config->new($self->root_dir . '/config.json');
    $self->storage; # create and cache storage connection...
    $self->session_storage;
    $self->{_config};
}

sub storage { # use this ?
    my $self = shift;
    return $self->{_storage} if $self->{_storage};

    my $storage_conf = $self->config->storage_params;
    foreach my $key (keys(%{$storage_conf})) {
        Whada::PrivStore->set_storage_configuration($key, $storage_conf->{$key});
    }
    $self->{_storage} = Whada::PrivStore->storage();
}

sub session_storage {
    my $self = shift;

    my $storage_conf = $self->config->storage_params;
    my $host = $storage_conf->{host} || 'localhost';
    my $port = $storage_conf->{port} || 3306;
    my $username = $storage_conf->{username};
    my $password = $storage_conf->{password};
    my $dsn;
    if ($host eq 'localhost' and not $port and $username eq 'root' and $password eq '') {
        $dsn = "DBI:mysql:database=whadasession;host=localhost";
    }
    else {
        $dsn = "DBI:mysql:database=whadasession;host=$host;port=$port";
    }
    DBI->connect_cached($dsn, $username, $password)
        or die $DBI::errstr;
}

filter 'check_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => HTTP::Session::Store::DBI->new({
                dbh => $self->session_storage(),
                expires => $self->config->{session}->{expires},
            }),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        if ($session->get('logged_in')) {
            $session->set('logged_in', 1);
            $c->stash->{username} = $session->get('username');
            $c->stash->{whada_privs} = decode_json($session->get('whada_privs') || '{}');
            $c->stash->{is_admin} = $session->get('is_admin') || $session->get('is_partial_admin');
        }
        $c->stash->{session} = $session;
        $session->response_filter($c->res);
        $app->($self, $c);
    }
};

filter 'require_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => HTTP::Session::Store::DBI->new({
                dbh => $self->session_storage(),
                expires => $self->config->{session}->{expires},
            }),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        unless ($session->get('logged_in')) {
            $c->halt(401, 'specified operations requires login, see /.');
            return;
        }
        $session->set('logged_in', 1);
        $c->stash->{session} = $session;
        $c->stash->{username} = $session->get('username');
        $c->stash->{whada_privs} = decode_json($session->get('whada_privs') || '{}');
        $c->stash->{is_admin} = $session->get('is_admin') || $session->get('is_partial_admin');
        $session->response_filter($c->res);
        $app->($self, $c);
    }
};

filter 'require_authenticated_admin' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => HTTP::Session::Store::DBI->new({
                dbh => $self->session_storage(),
                expires => $self->config->{session}->{expires},
            }),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        unless ($session->get('logged_in')) {
            $c->halt(401, 'specified operations requires login as Whada Admin member, see /.');
            return;
        }
        $session->set('logged_in', 1);
        $c->stash->{session} = $session;
        $c->stash->{username} = $session->get('username');
        $c->stash->{whada_privs} = decode_json($session->get('whada_privs') || '{}');
        $c->stash->{is_admin} = $session->get('is_admin') || $session->get('is_partial_admin');
        unless ($c->stash->{is_admin}) {
            $c->halt(401, 'specified operations requires login as Whada Admin member.');
            return;
        }
        $session->response_filter($c->res);
        $app->($self, $c);
    }
};

get '/' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $c->stash->{session};
    if ($session->get('logged_in')) { # menu for logged-in users
        $c->render('index.tx', {
            username => $session->get('username'),
            privileges => [sort(keys(%{$c->stash->{whada_privs}}))],
            privs => $c->stash->{whada_privs},
            notification => $session->remove('notification'),
            isadmin => $c->stash->{is_admin},
        });
    }
    else { # authentication form
        $c->render('login.tx', {
            notification => $session->remove('notification'),
        });
    }
};

post '/login' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $username = $c->req->param('username');
    my $password = $c->req->param('password');

    my $session = $c->stash->{session};
    my $entry;
    try {
        my @params = $self->config->engine_params($username, $password, 'WHADA');
        $entry = Whada::Engine->authenticate(@params);
    } catch {
        print STDERR "perl backend search failed with error: $_\n";
        $entry = undef;
    };

    if ($entry) {
        $session->set('logged_in', 1);
        my $cred = Whada::Credential->new({username => $username, privilege => 'WHADA+ADMIN'});
        my $privs = Whada::PrivStore->privileges($cred);
        my $is_admin = Whada::PrivStore->check($cred);
        $session->set('whada_privs', encode_json($privs));
        $session->set('username', $username);
        $session->set('is_admin', $is_admin);
        $session->set('is_partial_admin', scalar(grep {$_ =~ /^WHADA\+ADMIN\+.+$/} keys(%$privs)) > 0);
    }
    else {
        $session->set('logged_in', 0);
        $session->set('notification', 'check your password or WHADA privilege...');
    }
    $c->redirect('/');
};

get '/logout' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $c->stash->{session};
    $session->expire();
    $c->redirect('/');
};

get '/privs' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    my $privs = Whada::PrivStore->priv_data_list();
    $c->render_json([grep {$_->{name} !~ /^WHADA/} @{$privs}]);
};

get '/admin_privs' => [qw/require_authenticated_admin/] => sub {
    my ($self, $c) = @_;
    my $privs = Whada::PrivStore->priv_data_list();
    $c->render_json([grep {$_->{name} =~ /^WHADA/} @{$privs}]);
};

get '/priv/:privname' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    $c->render_json(Whada::PrivStore->priv_data($c->args->{privname}));
};

post '/priv/update' => [qw/require_authenticated_admin/] => sub {
    my ($self, $c) = @_;
    warnf ddf
    my $privilege = uc($c->req->parameters->{privilege});
    unless (Whada::PrivStore->priv_data($privilege)) {
        $c->render_json({result => JSON::false, message => 'unknown privilege:' . $privilege});
        return;
    }
    my $dst_type = $c->req->parameters->{dst_type};
    unless (Whada::PrivStore->check_priv_type($dst_type)) {
        warnf 'wrong privilege type:' . $dst_type;
        $c->render_json({result => JSON::false, message => 'wrong privilege type:' . $dst_type});
        return;
    }
    my $root_admin_priv = 'WHADA+ADMIN+' . (split(/\+/, $privilege))[0];
    my $check = Whada::PrivStore->check(Whada::Credential->new({
        username => $c->stash->{username},
        privilege => $root_admin_priv,
    }));
    unless ($check) {
        $c->render_json({result => JSON::false, message => 'permission denied: you do not have privilege:' . $root_admin_priv});
        return;
    }
    try {
        Whada::PrivStore->set_priv_type($privilege, $dst_type);
        $c->render_json({result => JSON::true, message => 'privilege type changed:' . $dst_type});
    } catch {
        warnf 'failed to save privilege:' . $privilege . ', error:' . ddf($_);
        $c->render_json({result => JSON::false, message => 'unknown error (maybe database error)'});
    };
};

post '/priv/create' => [qw/require_authenticated_admin/] => sub {
};

post '/priv/drop' => [qw/require_authenticated_admin/] => sub {
};

get '/users' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    $c->render_json(Whada::PrivStore->user_data_list());
};

get '/user/:username' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    $c->render_json(Whada::PrivStore->priv_data($c->args->{username}));
};

post '/user/update' => [qw/require_authenticated_admin/] => sub {
    my ($self, $c) = @_;
    my $operation = $c->req->parameters->{operation};
    unless ($operation eq 'allow' or $operation eq 'deny' or $operation eq 'remove') {
        return $c->render_json({result => JSON::false, message => 'invalid operation:' . $operation});
    }
    my $target_username = $c->req->parameters->{username};
    my $target_user_credential = Whada::Credential->new({username => $target_username});
    my $target = Whada::PrivStore->user_data($target_username);
    unless ($target->{privileges}) {
        return $c->render_json({result => JSON::false, message => 'unknown user:' . $target_username});
    }
    my $privilege = uc($c->req->parameters->{privilege});
    unless (Whada::PrivStore->priv_data($privilege)) {
        return $c->render_json({result => JSON::false, message => 'unknown privilege:' . $privilege});
    }
    my $root_admin_priv = 'WHADA+ADMIN+' . (split(/\+/, $privilege))[0];
    warnf ddf($c->stash);
    my $check = Whada::PrivStore->check(Whada::Credential->new({
        username => $c->stash->{username},
        privilege => $root_admin_priv,
    }));
    unless ($check) {
        return $c->render_json({result => JSON::false, message => 'permission denied: you do not have privilege:' . $root_admin_priv});
    }
    try {
        if ($operation eq 'allow') {
            Whada::PrivStore->allow_privileges($target_user_credential, $privilege);
        }elsif ($operation eq 'deny') {
            Whada::PrivStore->deny_privileges($target_user_credential, $privilege);
        }elsif ($operation eq 'remove') {
            delete $target->{privileges}->{$privilege};
            Whada::PrivStore->save_user_data($target);
        }
        $c->render_json({result => JSON::true, message => 'user privilege successfully updated.'});
    } catch {
        warnf 'failed to save user data:' . $target_username . ', error:' . ddf($_);
        $c->render_json({result => JSON::false, message => 'unknown error (maybe database error)'});
    };
};

post '/user/create' => [qw/require_authenticated_admin/] => sub {
};

post '/user/drop' => [qw/require_authenticated_admin/] => sub {
};

get '/check' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    my $username = $c->req->parameters->{username};
    my $privilege = $c->req->parameters->{privilege};
    if (Whada::PrivStore->check(Whada::Credential->new({usename => $username, privilege => $privilege}))) {
        $c->render_json({result => "Access allowed: $username -> $privilege"});
    }
    else {
        $c->render_json({result => "Access denied: $username -> $privilege"});
    }
};

1;
