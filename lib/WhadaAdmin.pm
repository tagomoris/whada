package WhadaAdmin;

use strict;
use warnings;
use utf8;

use Kossy;
use Cache::KyotoTycoon;

use WhadaAdmin::Config;

use Whada::Credential;

our $VERSION = 0.01;

sub load_config {
    my $self = shift;
    return $self->{_config} if $self->{_config};
    $self->{_config} = WhadaAdmin::Config->new($self->root_dir . '/config.json');
    $self->{_config};
}

my $storage_connection; # connection cache
sub storage {
    my $self = shift;
    return $storage_connection if $storage_connection;
    my $config = $self->load_config;
    my $ktconf = $config->{storage} || {};
    my $host = $ktconf->{host} || '127.0.0.1';
    my $port = $ktconf->{port} || 1978;
    $storage_connection = Cache::KyotoTycoon->new(host => $host, port => $port);
    $storage_connection;
}

filter 'check_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication correctly
        $c->stash->{authenticated} = $self->storage->get('authkey:' . random());
        $app->($self, $c);
    }
};

filter 'require_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication correctly
        my $authenticated = $self->storage->get('authkey:' . random());
        if (! $authenticated) {
            # TODO create response
            my $response;
            $c->halt($response);
            return;
        }
        $c->stash->{authenticated} = $authenticated;
        $app->($self, $c);
    }
};

filter 'require_authenticated_admin' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication WHADA+ADMIN correctly
        my $authenticated = $self->storage->get('authkey:' . random());
        if (! $authenticated) {
            # TODO create response
            my $response;
            $c->halt($response);
            return;
        }
        $c->stash->{authenticated} = $authenticated;
        $app->($self, $c);
    }
};

get '/' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    $c->render('index.tx', {user => $c->stash->{authenticated}}); # authentication form or menu
};

post '/login' => sub {
    $c->req->param('username'); ...;
    $c->redirect($c->req->uri_for('/'));
};

post '/logout' => sub {
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
