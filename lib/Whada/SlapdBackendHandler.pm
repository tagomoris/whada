package Whada::SlapdBackendHandler;

use strict;
use warnings;
use Carp;
use MIME::Base64;
use Try::Tiny;

use Whada::Logger;
use Whada::Engine;

sub new {
    my $class = shift;
    return bless {
        converter => 'Whada::Converter', # MUST be overwritten
        dictionary => 'Whada::Dictionary', # MUST be overwritten
        default_privilege => 'denied', # MUST be specified explicitly in subclass
        global_config => {},
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
    return 0 if $param !~ /^whadaBackend(.+)$/;

    $this->{config}->{lc($1)} = $value;
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
    try {
        my $config = $this->configurations;
        use Data::Dumper;
        warn Dumper $config;
        $entry = Whada::Engine->authorize({
            credential => ($this->{converter})->new({ldapquery => {base => $base, filter => $filterStr}})->credential(),
            dictionary => ($this->{dictionary})->new($config),
            logger => Whada::Logger->new('slapd', $config->{logpath}),
            default_privilege => $this->{default_privilege},
        });
    } catch {
        print STDERR "perl backend search failed with error: $_\n";
        $entry = undef;
    };
    return (0) unless defined $entry;
    my $pairs = join("\n", map {attribute_dump($_, $entry->get_value($_))} $entry->attributes());
    my $entryString = "dn: " . $entry->dn() . "\n" . $pairs . "\n";
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
