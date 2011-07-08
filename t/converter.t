use strict;

use Test::More;
use Test::Exception;

use_ok "Wada::Converter";
{
    throws_ok { Wada::Converter->new({}) } qr/invalid argument: only single key-value pair is allowed/, '';
    throws_ok { Wada::Converter->new({key1 => 1, key2 => 2}) } qr/invalid argument: only single key-value pair is allowed/;
    isa_ok (Wada::Converter->new({key => 'value'}), 'Wada::Converter');
}

{
    throws_ok { Wada::Converter->new({key => undef})->credential() } qr/invalid material for credential/;
    throws_ok { Wada::Converter->new({key => 1})->credential() } qr/undefined method: credential_from_key/;
}

done_testing;
