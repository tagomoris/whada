use strict;
use Test::More;
use Test::Exception;

use_ok "Wada::PrivStore";
use_ok "Wada::Credential";

{
    is (Wada::PrivStore::global_default_privilege(), 0);
}

{
    is (Wada::PrivStore::privType(undef), 'always_allow');
  TODO: {
        local $TODO = "update later with properly implemented privtypes for each privileges";
    }
}

{
    is_deeply (Wada::PrivStore::privileges({}), {});
  TODO: {
        local $TODO = "update later with properly implemented store/get privileges for users";
    }
}

{
    ok (Wada::PrivStore::check(Wada::Credential->new())); # always allowd
  TODO: {
        local $TODO = "PrivStore not implemented properly now.";
    }
}

done_testing;
