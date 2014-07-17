use strict;

use Test::More;

use_ok "Whada::Credential";
my $credential = Whada::Credential->new({ username => 'whada', password => 'passwd', mail => 'whada@tagomor.is', privilege => 'test' });

{
    isa_ok ($credential, 'Whada::Credential');
    is ($credential->{username}, 'whada');
    is ($credential->{password}, 'passwd');
    is ($credential->{mail}, 'whada@tagomor.is');
    is ($credential->{privilege}, 'TEST');
}

done_testing;
