package WhadaAdmin;

use strict;
use warnings;
use utf8;

use Kossy;

use WhadaAdmin::Config;
use WhadaAdmin::Util;

use Whada::PrivStore;
use Whada::Credential;

our $VERSION = 0.01;

sub config {
    my $self = shift;
    return $self->{_config} if $self->{_config};
    $self->{_config} = WhadaAdmin::Config->new($self->root_dir . '/config.json');
    $self->storage; # create and cache storage connection...
    $self->{_config};
}

sub storage {
    my $self = shift;
    return $self->{_storage} if $self->{_storage};

    my $storage_conf = $self->config->storage_params;
    my $host = $storage_conf->{host} || '127.0.0.1';
    my $port = $storage_conf->{port} || 1978;

    $self->{_storage} = Cache::KyotoTycoon->new(host => $host, port => $port);
    Whada::PrivStore->set_storage_connection($self->{_storage});
    $self->{_storage};
}

filter 'check_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication correctly
        $c->stash->{session} = $self->storage->get('session:' . random());
        $app->($self, $c);
    }
};

filter 'require_authenticated' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication correctly
        my $authenticated = $self->storage->get('session:' . random());
        if (! $authenticated) {
            # TODO create response
            my $response;
            $c->halt($response);
            return;
        }
        $c->stash->{session} = $authenticated;
        $app->($self, $c);
    }
};

filter 'require_authenticated_admin' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        # TODO: write authentication WHADA+ADMIN correctly
        my $authenticated = $self->storage->get('session:' . random());
        if (! $authenticated) {
            # TODO create response
            my $response;
            $c->halt($response);
            return;
        }
        $c->stash->{session} = $authenticated;
        $app->($self, $c);
    }
};

get '/' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    if ($self->stash->{authenticated}) {
        $c->render('index.tx', {user => $c->stash->{authenticated}}); # authentication form or menu
    }
    else {
        $c->render('login.tx');
    }
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
