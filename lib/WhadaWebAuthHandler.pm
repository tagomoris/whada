package WhadaWebAuthHandler;

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

use WhadaWebAuth::Config;

use Whada::Engine;
use Whada::PrivStore;
use Whada::Credential;

use Net::OpenID::Server;

# for debug...
use Data::Dumper;

our $VERSION = 0.01;

sub config {
    my $self = shift;
    return $self->{_config} if $self->{_config};
    $self->{_config} = WhadaWebAuth::Config->new($self->root_dir . '/config.json');
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
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaauth_sid'),
            request => $c->req
        );
        if ($session->get('logged_in')) {
            $session->set('logged_in', 1);
            $c->stash->{username} = $session->get('username');
            $c->stash->{whada_privs} = decode_json($session->get('whada_privs') || '{}');
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
            state => HTTP::Session::State::Cookie->new(cookie_key => 'whadaauth_sid'),
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

######
# OpenID setup_url => 'http://hostname' + '/openid/:priv/setup'
# OpenID endpoint_url => 'http://hostname' + '/openid/:priv/auth'
# OpenID identity url => 'http://hostname' + '/openid/:priv/user/:username'
######

sub openid_server {
    my $self = shift;
    my $c = shift;

    unless ($self->config->{webauth}->{openid}) {
        warnf "openid handler disabled in config.json";
        return undef;
    }
    my $config_openid = $self->config->{webauth}->{openid};
    my $env = $c->req->env;
    my $username = $c->stash->{username};
    my $hostname = $config_openid->{hostname};
    my $secret_salt = $config_openid->{server_secret_salt} || (sub {use Sys::Hostname qw//; Sys::Hostname::hostname();})->();

    my $privilege = ($c->req->path =~ m!/openid/([+a-zA-Z]+)/(setup|auth)!)[1];
    unless ($privilege) {
        warnf "unknown path for openid_server: " . $c->req->path;
        return undef;
    }

    return Net::OpenID::Server->new(
        get_args     => $env,
        post_args    => $env,
        get_user     => sub { $username; },
        get_identity => sub { "http://$hostname/openid/$privilege/auth"; },
        is_identity  => sub { my ($u,$url)=@_; $u and $url eq "http://$hostname/openid/$privilege/$username/$u"; },
        is_trusted   => sub {
            my ($u, $trust_root, $is_identity) = @_;
            return 0 unless $u and $is_identity;
            #TODO implement later.
            return 0;
        },
        setup_url    => "http://$hostname/openid/$privilege/setup",
        endpoint_url => "http://$hostname/openid/$privilege/auth",
    );
}

get '/' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    #TODO login form or none
};

get '/openid/:priv/setup' => sub {
    my ($self, $c) = @_;
    my $server = $self->openid_server($c);
    my ($type, $data) = $server->handle_page;
    if ($type eq "redirect") {
        $c->redirect($data);
    } elsif ($type eq "setup") {
        my %setup_opts = %$data;
        # ... show them setup page(s), with options from setup_map
        # it's then your job to redirect them at the end to "return_to"
        # (or whatever you've named it in setup_map)
        warnf "setup with:" . ddf($data);
        $c->halt('debugging!');
    } else {
        $c->res->status(200);
        $c->res->content_type($type);
        $c->res->body($data);
        $c->res;
    }
};

get '/openid/:priv/auth' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    # if not logged in yet, store redirect url to session, and show login page.
    # if logged in already, redirect directly.

    #TODO what uri handler i should call openid_server->handle() ?
    my $server = $self->openid_server($c);
    my ($type, $data) = $server->handle_page;
    if ($type eq "redirect") {
        $c->redirect($data);
    } elsif ($type eq "setup") {
        my %setup_opts = %$data;
        # ... show them setup page(s), with options from setup_map
        # it's then your job to redirect them at the end to "return_to"
        # (or whatever you've named it in setup_map)
        warnf "setup with:" . ddf($data);
        $c->halt('debugging!');
    } else {
        $c->res->status(200);
        $c->res->content_type($type);
        $c->res->body($data);
        $c->res;
    }
};

get '/openid/:priv/user/:username' => sub {
    my ($self, $c) = @_;
    #TODO check if this handler is requested or not in openid auth workflow
    my $server = $self->openid_server($c);
    my ($type, $data) = $server->handle_page;
    if ($type eq "redirect") {
        $c->redirect($data);
    } elsif ($type eq "setup") {
        my %setup_opts = %$data;
        # ... show them setup page(s), with options from setup_map
        # it's then your job to redirect them at the end to "return_to"
        # (or whatever you've named it in setup_map)
        warnf "setup with:" . ddf($data);
        $c->halt('debugging!');
    } else {
        $c->res->status(200);
        $c->res->content_type($type);
        $c->res->body($data);
        $c->res;
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

1;
