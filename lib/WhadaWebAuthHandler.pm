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
use Digest::SHA qw//;

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
        $session->response_filter($c->res);
        $app->($self, $c);
    }
};

filter 'add_openid_headers' => sub {
    my $app = shift;
    sub {
        my ($self, $c) = @_;
        return $app->($self, $c) unless $self->config->{webauth} && $self->config->{webauth}->{openid};
        return $app->($self, $c) unless $c->req->path =~ m!^/openid/!;

        my $hostname = $self->config->{webauth}->{openid}->{hostname};
        my $openid_args = openid_parse_path($c->req->path);
        if ($openid_args->{operation} and $openid_args->{operation} eq 'u') {
            $c->res->header('X-XRDS-Location' => "http://$hostname/openid/" . $openid_args->{privilege} . "/signon.xrds");
        }
        else {
            $c->res->header('X-XRDS-Location' => "http://$hostname/openid/" . $openid_args->{privilege} . "/server.xrds");
        }
        $app->($self, $c);
    }
};

######
# OpenID setup_url => 'http://hostname' + '/openid/:priv/setup'
# OpenID endpoint_url => 'http://hostname' + '/openid/:priv/auth'
# OpenID identity url => 'http://hostname' + '/openid/:priv/user/:username'
######

sub openid_parse_path {
    my $path = shift;
    my @items = ($path =~ m!^/openid/([+a-zA-Z]+)(/(signon\.xrds|server\.xrds|setup|auth|u)(/(.*))?)?$!);
    return undef unless @items;
    return {
        operation => $items[2],
        privilege => $items[0],
        username => $items[4],
    };
}

sub openid_server {
    my $self = shift;
    my $c = shift;

    unless ($self->config->{webauth}->{openid}) {
        warnf "openid handler disabled in config.json";
        return undef;
    }
    my $config_openid = $self->config->{webauth}->{openid};
    my $env = $c->req->env;
    warn "WITH env:";
    warn Dumper $env;
    my $username = $c->stash->{username};
    my $hostname = $config_openid->{hostname};
    my $secret_salt = $config_openid->{server_secret_salt} || (sub {use Sys::Hostname qw//; Sys::Hostname::hostname();})->();

    my $openid_args = openid_parse_path($c->req->path);
    unless ($openid_args) {
        warnf "unknown path for openid_server: " . $c->req->path;
        return undef;
    }
    my $privilege = $openid_args->{privilege};

    return Net::OpenID::Server->new(
        get_args     => $env,
        post_args    => $env,
        get_user     => sub {
            warn "ON get_user";
            warn Dumper [@_, $username];
            $username;
        },
        get_identity => sub {
            warn "ON get_identity";
            warn Dumper [@_];
            "http://$hostname/openid/$privilege/auth";
        },
        is_identity  => sub {
            my ($u,$url)=@_;
            warn "ON is_identity";
            warn Dumper [@_, $hostname, $privilege];
            $u and $url eq "http://$hostname/openid/$privilege/u/$u";
        },
        is_trusted   => sub {
            my ($u, $trust_root, $is_identity) = @_;
            return 0 unless $u and $is_identity;
            #TODO implement later.
            return $is_identity;
        },
        server_secret => sub {
            Digest::SHA::sha1_hex($secret_salt . (time / (86400 * 3 + length($secret_salt))));
        },
        # setup_url    => "http://$hostname/openid/$privilege/setup",
        setup_url    => "http://$hostname/openid/$privilege/auth",
        endpoint_url => "http://$hostname/openid/$privilege/auth",
    );
}

get '/' => sub {
    my ($self, $c) = @_;
    $c->halt(404);
};

get '/openid/:priv' => [qw/check_authenticated add_openid_headers/] => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
    $c->render('auth_top.tx', {
        protocol => 'OpenID',
        privilege => $c->args->{priv},
    });
};

get '/openid/:priv/signon.xrds' => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
    my $openid_args = openid_parse_path($c->req->path);
    my $privilege = $openid_args->{privilege};
    my $hostname = $self->config->{webauth}->{openid}->{hostname};
    $c->res->status(200);
    $c->res->content_type('application/xrds+xml');
    $c->res->body(<<EOXRDS);
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://\$xrds"
    xmlns:openid="http://openid.net/xmlns/1.0"
    xmlns="xri://\$xrd*(\$v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>http://$hostname/openid/$privilege/auth</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOXRDS
    $c->res;
};

get '/openid/:priv/server.xrds' => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
    my $openid_args = openid_parse_path($c->req->path);
    my $privilege = $openid_args->{privilege};
    my $hostname = $self->config->{webauth}->{openid}->{hostname};
    $c->res->status(200);
    $c->res->content_type('application/xrds+xml');
    $c->res->body(<<EOXRDS);
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://\$xrds"
    xmlns:openid="http://openid.net/xmlns/1.0"
    xmlns="xri://\$xrd*(\$v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/server</Type>
      <URI>http://$hostname/openid/$privilege/auth</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOXRDS
    $c->res;
};

# get '/openid/:priv/setup' => sub {
#     my ($self, $c) = @_;
#     unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
#         $c->halt(404);
#     }
#     my $server = $self->openid_server($c);
#     my ($type, $data) = $server->handle_page;
#     if ($type eq "redirect") {
#         $c->redirect($data);
#     } elsif ($type eq "setup") {
#         my %setup_opts = %$data;
#         # ... show them setup page(s), with options from setup_map
#         # it's then your job to redirect them at the end to "return_to"
#         # (or whatever you've named it in setup_map)
#         warnf "setup with:" . ddf($data);
#         $c->halt('debugging!');
#     } else {
#         $c->res->status(200);
#         $c->res->content_type($type);
#         $c->res->body($data);
#         $c->res;
#     }
# };

get '/openid/:priv/auth' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
    # check logged in or not
    # NOT: -> set redirect_to to session, and show login page (to POST /login)
    # ELSE: -> check privilege and redirect redirect_to

    #TODO what uri handler i should call openid_server->handle() ?
    warn Dumper $c->req->query_parameters;
# $VAR1 = bless( {
#                  'openid.sreg.required' => 'nickname,email',
#                  'openid.ns.sreg' => 'http://openid.net/extensions/sreg/1.1',
#                  'openid.ns.ax' => 'http://openid.net/srv/ax/1.0',
#                  'openid.mode' => 'checkid_setup',
#                  'openid.claimed_id' => 'http://specs.openid.net/auth/2.0/identifier_select',
#                  'openid.ns' => 'http://specs.openid.net/auth/2.0',
#                  'openid.identity' => 'http://specs.openid.net/auth/2.0/identifier_select',
#                  'openid.ax.mode' => 'fetch_request',
#                  'openid.realm' => 'http://ld-git.data-hotel.net/',
#                  'openid.return_to' => 'http://ld-git.data-hotel.net/sessions?_method=post&open_id_complete=1',
#                  'openid.sreg.optional' => 'fullname'
#                }, 'Hash::MultiValue' );

    my $server = $self->openid_server($c);
    my ($type, $data) = $server->handle_page;
    warn Dumper {type => $type, data => $data};
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

post '/openid/:priv/auth' => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
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

get '/openid/:priv/u/:username' => [qw/check_authenticated add_openid_headers/] => sub {
    my ($self, $c) = @_;
    unless ($self->config->{webauth} && $self->config->{webauth}->{openid}) {
        $c->halt(404);
    }
    my $openid_args = openid_parse_path($c->req->path);
    my $hostname = $self->config->{webauth}->{openid}->{hostname};

    my $authorized = 'unknown';
    if ($c->stash->{username} and $c->stash->{username} eq $c->args->{username}) {
        my $entry = try {
            my @params = $self->config->engine_params($openid_args->{username}, undef, $openid_args->{privilege});
            Whada::Engine->authorize(@params);
        } catch {
            print STDERR "authorize test failed with error: $_\n";
            undef;
        };
        $authorized = $entry ? 'ALLOWED' : 'REJECTED';
    }
    $c->render('identity.tx', {
        logged_in => $c->stash->{session}->get('logged_in'),
        username => $c->args->{username},
        privilege => $c->args->{priv},
        authorized => $authorized,
        auth_url => "http://$hostname/openid/" . $openid_args->{privilege} . '/auth',
        identity_url => "http://$hostname/openid/" . $openid_args->{privilege} . '/u/' . $openid_args->{username},
    })
};

post '/login' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $username = $c->req->param('username');
    my $password = $c->req->param('password');
    my $session = $c->stash->{session};
    my $entry;
    try {
        my @params = $self->config->engine_params($username, $password, 'WHADA+LOGINONLY');
        $entry = Whada::Engine->authenticate(@params);
    } catch {
        print STDERR "authentication failed with error: $_\n";
        $entry = undef;
    };

    if ($entry) {
        $session->set('logged_in', 1);
        my $cred = Whada::Credential->new({username => $username});
        my $privs = Whada::PrivStore->privileges($cred);
        $session->set('whada_privs', encode_json($privs));
        $session->set('username', $username);
    }
    else {
        $session->set('logged_in', 0);
        $session->set('notification', 'check your password or WHADA privilege...');
    }
    $c->redirect($c->req->referer || '/');
};

get '/logout' => [qw/check_authenticated/] => sub {
    my ($self, $c) = @_;
    my $session = $c->stash->{session};
    $session->expire();
    $c->redirect($c->req->referer || '/');
};

1;
