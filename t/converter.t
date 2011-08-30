use strict;

use Test::More;
use Test::Exception;

use_ok "Whada::Converter";
{
    throws_ok { Whada::Converter->new({}) } qr/invalid argument: only single key-value pair is allowed/, '';
    throws_ok { Whada::Converter->new({key1 => 1, key2 => 2}) } qr/invalid argument: only single key-value pair is allowed/;
    isa_ok (Whada::Converter->new({key => 'value'}), 'Whada::Converter');
}

{
    throws_ok { Whada::Converter->new({key => undef})->credential() } qr/invalid material for credential/;
    throws_ok { Whada::Converter->new({key => 1})->credential() } qr/undefined method: credential_from_key/;
}

done_testing;
