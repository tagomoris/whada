package WhadaAdmin::Config;

use strict;
use warnings;
use utf8;
use Carp;

use Try::Tiny;

use JSON;

## example
# my $x = {
#     load_path => [
#         '/Users/tagomoris/Documents/ldwhada/lib',
#         '/home/edge-dev/ldwhada'
#     ],
#     auth_source => {
#         type => 'ldap',
#         host => '192.168.0.1', # or '192.168.0.1:389'
#         binddn => 'cn=Manager,cn=Users,dc=ad,dc=intranet',
#         bindpassword => 'secret',
#         base => 'cn=Users,dc=ad,dc=intranet',
#         attribute => 'sAMAccountName',    # in case of builtin Whada::Converter::LDAP
#         converter_module => 'LDWhada::Converter', # or use plugin module for your environment
#     },
#     storage => {
#         type => 'KT',
#         host => 'localhost',
#         port => 1978,
#     },
#     logger => {
#         path => '/var/log/whada/admin',
#     },
# };

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

    $self->load_external_modules();

    # try engine_params
    $self->engine_params('dummy', 'xdummy', 'privdummy');

    return $self;
}

sub load_external_modules {
    my $self = shift;
    foreach my $path (@{$self->{load_path}}) {
        use lib $path;
    }
    if ($self->{auth_source}->{type} eq 'ldap') {
        use Whada::Converter::LDAP;
        use Whada::Dictionary::LDAP;
    }
    if ($self->{auth_source}->{converter_module}) {
        use $self->{auth_source}->{converter_module};
    }
}

sub storage_params {
    my $self = shift;

    # default is KT default port of localhost
    return {host => 'localhost', port => 1978} unless $self->{storage};

    if (defined $self->{storage}->{type} and $self->{storage}->{type} eq 'KT') {
        return {
            host => ($self->{storage}->{host} || 'localhost'),
            port => ($self->{storage}->{port} || 1978),
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
        my $source = $config->{_config}->{auth_source};
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
    else {
        croak 'unknown auth_source type:' . $config->{_config}->{auth_source}->{type};
    }
    return (
        credential => $credential,
        dictionary => $dictionary,
        logger => Whada::Logger->new('WhadaWebAdmin', ($config->{logger}->{path} || '/tmp/whada.admin.log')),
        default_privilege => 'denied'
    );
}

1;
