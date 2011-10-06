package WhadaAdmin::Config;

use strict;
use warnings;
use utf8;
use Carp;

use Try::Tiny;

use JSON;

use Whada::Logger;

sub new {
    my $this = shift;
    my $path = shift;
    open( my $fh, '<', $path) or die $!;
    my $json_string = join('', <$fh>);
    close($fh);
    my $json_obj;
    try {
        $json_obj = decode_json($json_string);
    } catch {
        croak "configuration load error (json parse error):" . $_;
    };
    my $self = bless $json_obj, $this;

    $self->{session} ||= {};
    $self->{session}->{expires} ||= 1800; # 30 min
    $self->load_external_modules();

    # try engine_params
    $self->engine_params('dummy', 'xdummy', 'privdummy');

    return $self;
}

sub require_module {
    my ($mod) = @_;
    $mod =~ s/::/\//g;
    require "$mod.pm";
}

sub load_external_modules {
    my $self = shift;
    foreach my $path (@{$self->{load_path}}) {
        push @INC, $path;
    }
    if ($self->{auth_source}->{type} eq 'ldap') {
        use Whada::Converter::LDAP;
        use Whada::Dictionary::LDAP;
    }
    if ($self->{auth_source}->{type} eq 'file') {
        use Whada::Dictionary::File;
    }
    if ($self->{auth_source}->{converter_module}) {
        my $mod = $self->{auth_source}->{converter_module};
        require_module $mod;
    }
}

sub storage_params {
    my $self = shift;

    # default is KT default port of localhost
    return {host => 'localhost', username => 'root', password => ''} unless $self->{storage};

    if (defined $self->{storage}->{type} and $self->{storage}->{type} eq 'DB') {
        return {
            host => ($self->{storage}->{host} || 'localhost'),
            port => $self->{storage}->{port},
            username => $self->{storage}->{username},
            password => $self->{storage}->{password},
        };
    }
    croak 'unknown storage type:' . $self->{storage}->{type};
}

sub engine_params {
    my $self = shift;
    my ($username, $password, $priv) = @_;
    my $credential = Whada::Credential->new({username => $username, password => $password, privilege => $priv});
    my $dictionary;
    my $converter;
    if ($self->{auth_source} and $self->{auth_source}->{type} eq 'ldap') {
        my $source = $self->{auth_source};
        my $converter_module;
        if ($source->{converter_module}) {
            $converter_module = $source->{converter_module};
        } else {
            my $converter_module = 'Whada::Converter::LDAP';
            $converter_module->set_global_default(filter => {attribute => $source->{attribute}});
        }
        $dictionary = Whada::Dictionary::LDAP->new($converter_module, {
            server => $source->{host},
            binddn => $source->{binddn},
            bindpassword => $source->{bindpassword},
            base => $source->{base},
        });
    }
    elsif ($self->{auth_source} and $self->{auth_source}->{type} eq 'file') {
        my $source = $self->{auth_source};
        $dictionary = Whada::Dictionary::File->new(undef, {path => $source->{path}, salt => $source->{salt}});
    }
    else {
        croak 'unknown auth_source type:' . $self->{auth_source}->{type};
    }
    return (
        credential => $credential,
        dictionary => $dictionary,
        logger => Whada::Logger->new('WhadaWebAdmin', (($self->{logger} && $self->{logger}->{path}) || '/tmp/whada.admin.log')),
        default_privilege => 'denied'
    );
}

1;
