package Wada::Logger;

use strict;
use warnings;
use Carps;

use File::Stamped;
use Log::Minimal;

sub new {
    my $this = shift;
    my ($handler, $path) = @_;
    $path = '/var/log/wada.log.%Y%m%d' unless $path;
    return bless {handler => $handler, fh => File::Stamped->new(pattern => $path)}, $this;
}

sub logging {
    my $self = shift;
    my ($credential, $message) = @_;

    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =
        localtime(time);
    my $time = sprintf(
        "%04d-%02d-%02dT%02d:%02d:%02d",
        $year + 1900,
        $mon + 1, $mday, $hour, $min, $sec
    );
    # 2010-10-20T00:25:17 slapd [BTS] tagomoris: authorized (without password verification)
    # 2010-10-20T00:25:17 slapd [BTSUPDATE] tagomoris: not authorized
    # 2010-10-20T00:25:19 OAuth [DEPLOY] daisukem: success
    # 2010-10-20T00:25:21 OpenID [CISETTING] azuma: authentication failed
    print $self->{fh} $time, " ", $self->{handler}, " ", $credential->logformat, ":", $message, "\n";
}

1;
