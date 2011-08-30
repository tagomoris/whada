use strict;
use Test::More;
use Test::Exception;

use_ok "Whada::PrivStore";
use_ok "Whada::Credential";

{
    is (Whada::PrivStore::global_default_privilege(), 0);
}

{
    is (Whada::PrivStore::privType(undef), 'always_allow');
  TODO: {
        local $TODO = "update later with properly implemented privtypes for each privileges";
    }
}

{
    is_deeply (Whada::PrivStore::privileges({}), {});
  TODO: {
        local $TODO = "update later with properly implemented store/get privileges for users";
    }
}

{
    ok (Whada::PrivStore::check(Whada::Credential->new())); # always allowd
  TODO: {
        local $TODO = "PrivStore not implemented properly now.";
    }
}

done_testing;
