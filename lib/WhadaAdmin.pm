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
        $session->set('is_partial_admin', scalar(grep {$_ =~ /^WHADA\+.+\+ADMIN$/} keys(%$privs)) > 1);
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
    $c->render_json(Whada::PrivStore->priv_data($c->args->{labelname}));
};

post '/priv/create' => [qw/require_authenticated_admin/] => sub {
};

post '/priv/update' => [qw/require_authenticated_admin/] => sub {
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

post '/user/create' => [qw/require_authenticated_admin/] => sub {
};

post '/user/update' => [qw/require_authenticated_admin/] => sub {
};

post '/user/drop' => [qw/require_authenticated_admin/] => sub {
};

1;
