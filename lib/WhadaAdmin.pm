package WhadaAdmin;

use strict;
use warnings;
use utf8;

use Cache::KyotoTycoon;
use HTTP::Session;
use HTTP::Session::Store::KyotoTycoon;
use HTTP::Session::State::Cookie;

use Kossy;

use WhadaAdmin::Config;

use Whada::PrivStore;
use Whada::Credential;

our $VERSION = 0.01;

sub config {
    my $self = shift;
    return $self->{_config} if $self->{_config};
    $self->{_config} = WhadaAdmin::Config->new($self->root_dir . '/config.json');
    $self->storage; # create and cache storage connection...
    $self->session_storage;
    $self->{_config};
}

sub storage {
    my $self = shift;
    return $self->{_storage} if $self->{_storage};

    my $storage_conf = $self->config->storage_params;
    my $host = $storage_conf->{host} || '127.0.0.1';
    my $port = $storage_conf->{port} || 1978;
    my $dbname = 'whadaadmin.kch';

    $self->{_storage} = Cache::KyotoTycoon->new(host => $host, port => $port, db => $dbname);
    Whada::PrivStore->set_storage_connection($self->{_storage});
    $self->{_storage};
}

sub session_storage {
    my $self = shift;
    return $self->{_session_storage} if $self->{_session_storage};

    my $storage_conf = $self->config->storage_params;
    my $host = $storage_conf->{host} || '127.0.0.1';
    my $port = $storage_conf->{port} || 1978;
    my $dbname = 'adminsession';
    my $expires = 60; # 3 * 3600 # 3 hours

    $self->{_session_storage} = HTTP::Session::Store::KyotoTycoon->new(
        host => $host,
        port => $port,
        db => $dbname,
        expires => $expires
    );
}

filter 'check_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => $self->session_storage(),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        use Data::Dumper;
        warn Dumper $session;
        if ($session->get('logged_in')) {
            $session->set('logged_in', 1);
        }
        $c->stash->{session} = $session;
        $c->stash->{username} = undef;
        # $c->stash->{session}->response_filter($c->res);
        $app->($self, $c);
    }
};

filter 'require_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => $self->session_storage(),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        use Data::Dumper;
        warn Dumper $session;
        unless ($session->get('logged_in')) {
            warn Dumper $c->res;
            # $session->response_filter($c->res);
            # warn Dumper $c->res;
            $c->halt(401, 'specified operations requires login, see /.');
            return;
        }
        # $session->set('logged_in', 1);
        $c->stash->{session} = $session;
        $c->stash->{username} = $session->get('username');
        $c->stash->{whada_privs} = decode_json($session->get('whada_privs') || '{}');
        # $c->stash->{session}->response_filter($c->res);
        $app->($self, $c);
    }
};

filter 'require_authenticated_admin' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        my $session = HTTP::Session->new(
            store => $self->session_storage(),
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaadmin_sid'),
            request => $c->req
        );
        use Data::Dumper;
        warn Dumper $session;
        unless ($session->get('logged_in')) {
            warn Dumper $c->res;
            # $session->response_filter($c->res);
            # warn Dumper $c->res;
            $c->halt(401, 'specified operations requires login as Whada Admin member, see /.');
            return;
        }
        my $privs = decode_json($session->get('whada_privs') || '{}');
        unless ($privs->{'WHADA+ADMIN'}) {
            $c->halt(401, 'specified operations requires login as Whada Admin member.');
            return;
        }
        # $session->set('logged_in', 1);
        $c->stash->{session} = $session;
        $c->stash->{username} = $session->get('username');
        $c->stash->{whada_privs} = $privs;
        # $c->stash->{session}->response_filter($c->res);
        $app->($self, $c);
    }
};

get '/' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $c->stash->{session};
    if ($c->stash->{username}) { # menu for logged-in users
        $c->render('index.tx', {
            username => $session->get('username'),
            privileges => $c->stash->{whada_privs},
        });
    }
    else { # authentication form
        $c->render('login.tx');
    }
    $session->response_filter($c->res);
    $c->res;
};

# for html debugging
get '/index' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $c->stash->{session};
    $c->render('index.tx', {
        username => $session->get('username'),
        privileges => [keys(%{$c->stash->{whada_privs}})],
    });
    $session->response_filter($c->res);
    $c->res;
};

post '/login' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $username = $c->req->param('username');
    my $password = $c->req->param('password');

    my $session = $self->stash->{session};
    my $entry;
    try {
        $entry = Whada::Engine->authenticate($self->conf->engine_params($username, $password, 'WHADA'));
    } catch {
        print STDERR "perl backend search failed with error: $_\n";
        $entry = undef;
    };

    if ($entry) {
        $session->set('logged_in', 1);
        my $privs = Whada::PrivStore->privileges(Whada::Credential->new({username => $username}));
        $session->set('whada_privs', encode_json($privs));
    }
    else {
        $session->set('logged_in', 0);
    }
    $c->redirect('/');
    $session->response_filter($c->res);
    $c->res;
};

post '/logout' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $self->stash->{session};
    $session->expire();
    $c->redirect('/');
    # $session->response_filter($c->res);
    $c->res;
};

get '/labels' => [qw/require_authenticated/] => sub {
};

get '/label/:labelname' => [qw/require_authenticated/] => sub {
};

post '/label/create' => [qw/require_authenticated_admin/] => sub {
};

post '/label/update' => [qw/require_authenticated_admin/] => sub {
};

post '/label/drop' => [qw/require_authenticated_admin/] => sub {
};

get '/users' => [qw/require_authenticated/] => sub {
};

get '/user/:username' => [qw/require_authenticated/] => sub {
    my ($self, $c) = @_;
    # $c->args->{username};
};

post '/user/create' => [qw/require_authenticated_admin/] => sub {
};

post '/user/update' => [qw/require_authenticated_admin/] => sub {
};

post '/user/drop' => [qw/require_authenticated_admin/] => sub {
};

1;
