use inc::Module::Install;
name 'Wada';
all_from 'lib/Wada.pm';

# requires 'ModuleName';
requires 'Net::LDAP';
requires 'Net::LDAP::Filter';
# requires 'Net::LDAP::FilterBuilder';
requires 'File::Stamped';

tests 't/*.t';
test_requires 'Test::More';

auto_set_repository;
WriteAll;
