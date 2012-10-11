package Whada::SlapdBackendHandler;

use strict;
use warnings;
use Carp;
use MIME::Base64;
use Try::Tiny;

use Whada::Logger;
use Whada::Engine;
use Whada::PrivStore;

use WhadaAdmin::Config;

sub new {
    my $class = shift;
    return bless {
        converter => 'Whada::Converter', # MUST be overwritten
        dictionary => 'Whada::Dictionary', # MUST be overwritten
        global_config => {}, # maybe overwritten in subclass
        config => {}
    }, $class;
}

sub attribute_dump {
    my ($attr, $value) = @_;
    if ($attr =~ /\Aobject(s|gu)id\Z/i) {
        my $encoded = encode_base64($value);
        chomp $encoded;
        return $attr . ': ' . $encoded;
    }
    return $attr . ': ' . $value;
}

sub configurations {
    my $this = shift;
    return {%{$this->{global_config}}, %{$this->{config}}};
}

sub config {
    my $this = shift;
    my ($param, $value) = @_;

    if ($param eq 'whadaConfigFile') {
        my $config = WhadaAdmin::Config->new($value);
        die "auth_source not found" unless $config->{auth_source} and $config->{auth_source}->{type};
        if ($config->{auth_source}->{type} eq 'ldap') {
            $this->{dictionary} = 'Whada::Dictionary::LDAP';
            my $source = $config->{auth_source};
            if ($source->{converter_module}) {
                $this->{converter} = $source->{converter_module};
            }elsif ($source->{attribute}) {
                $this->{converter} = 'Whada::Converter::LDAP';
                Whada::Converter::LDAP->set_global_default(filter => {attribute => $source->{attribute}});
            }else{
                die "unknown converter pattern...";
            }
            $this->{config}->{server} = $source->{host};
            $this->{config}->{binddn} = $source->{binddn};
            $this->{config}->{bindpassword} = $source->{bindpassword};
            $this->{config}->{base} = $source->{base};
        }
        elsif ($config->{auth_source}->{type} eq 'file') {
            $this->{dictionary} = 'Whada::Dictionary::File';
            $this->{converter} = 'Whada::Converter::LDAP';
        }
        else {
            die "unknown auth_source type...";
        }
        die "storage not found" unless $config->{storage} and $config->{storage}->{type};
        if ($config->{storage}->{type} eq 'DB') {
            my $storage_conf = $config->storage_params;
            foreach my $key (keys(%{$storage_conf})) {
                Whada::PrivStore->set_storage_configuration($key, $storage_conf->{$key});
            }
        }
        else {
            die "unknown storage type...";
        }
    }
    elsif ($param =~ /^whada(.+)$/) {
        my $param_name = $1;
        if ($param_name eq 'LogPath') {
            $this->{config}->{logpath} = $value;
        }
        elsif ($param_name eq 'Suffix') {
            $this->{config}->{suffix} = $value;
        }
    }
    return 0;
}

sub init {
    return 0;
}

sub search {
    my $this = shift;
    my ($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs ) = @_;

    # $filterStr: (&(objectClass=*)(uid=tagomoris)), (&(objectClass=*)(MAIL=tagomoris@livedoor.jp))
    my $entry;
    my $credential;
    try {
        my $config = $this->configurations;
        $credential = ($this->{converter})->new({ldapquery => {base => $base, filter => $filterStr}})->credential();
        $entry = Whada::Engine->authorize(
            credential => $credential,
            dictionary => ($this->{dictionary})->new($this->{converter}, $config),
            logger => Whada::Logger->new('slapd', $config->{logpath}),
        );
    } catch {
        print STDERR "perl backend search failed with error: $_\n";
        $entry = undef;
    };
    return (0) unless defined $entry;
    my $pairs = join("\n", map {attribute_dump($_, $entry->get_value($_))} $entry->attributes());
    my @additionals = (
        "dn: " . $entry->dn(),
    );
    my $entryString = join("\n", @additionals) . "\n" . $pairs . "\n";
    return (0, $entryString);
}

sub compare {
    croak "not implemented";
}

sub bind {
    # TODO write
    my $this = shift;
    # you cannot bind with virtual entries.
    return 0;
}

sub modify {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
    return 0;
}

sub add {
    my $this = shift;
    # you cannot add entries to virtual entries.
    return 0;
}

sub modrdn {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
    return 0;
}

sub delete {
    my $this = shift;
    # you cannot do any modifications to virtual entries.
}

1;
