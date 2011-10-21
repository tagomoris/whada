use inc::Module::Install;
name 'Whada';
all_from 'lib/Whada.pm';

requires 'Scalar::Util';
requires 'Plack';
requires 'Plack::Middleware::Static';
requires 'Plack::Middleware::ReverseProxy';
requires 'Starman';
requires 'Router::Simple';
requires 'Cwd';
requires 'File::Basename';
requires 'Text::Xslate', 1.1003;
requires 'Text::Xslate::Bridge::TT2Like';
requires 'Try::Tiny', 0.09;
requires 'Class::Accessor::Lite';
requires 'JSON';
requires 'JSON::XS';

requires 'URI::Escape';

requires 'Log::Minimal';
requires 'File::Stamped';

requires 'DBI';
requires 'DBD::mysql';
requires 'HTTP::Session';
requires 'HTTP::Session::Store::DBI';
requires 'HTTP::Session::State::Cookie';

requires 'Net::LDAP';
requires 'Net::LDAP::Filter';
requires 'Net::OpenID::Server';
requires 'Math::BigInt::GMP';

tests 't/*.t';
test_requires 'Test::More';

WriteAll;
