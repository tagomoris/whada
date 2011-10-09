# shib

* http://github.com/tagomoris/whada

## DESCRIPTION

'whada' is authentication/authorization engine, works with multi-protocol for clients, multi-source for acount data, and original authority information database.

'whada' can allow/deny permissions for users for each privilege labels independently of account data source. You can control these settings on web control panel, and that change is enable immediately.

But now, protocols are limited:

* for clients: LDAP only
* for account data: LDAP or File (username - password hash pairs)

For future:

* for clients: LDAP, OpenID and OAuth(v1)
* for account data: LDAP, File and ? (MySQL? NIS? or ...?)

## Requirements

* UNIX like system (Linux, Mac OSX, ...)
* Perl (recent version)
  * developed on perl 5.14.x
* MySQL 5.x
* Slapd (OpenLDAP Server) with perl-backend support
  * Debian package seems OK
  * RPM (for CentOS 5) and Installed on OSX doesn't support perl-backend
  * Build process is in 'Environment Setting' section

## Environment Setting

### Perl

Whada requires modern perl, and doesn't works well with 5.8.x. So your system perl's version is 5.8.x, you should install recent version like 5.14.x as system perl (or perlbrew perl of root user).

### OpenLDAP Server

If your system's openldap package doesn't support perl-backend, you must build openldap from source with perl-backend.

* Download from OpenLDAP source tarball
  * http://www.openldap.org/software/download/
  * We used latest release on Sep 2011, 2.4.26.
* Build and install
  * Extract, configure, make and make install as root (for perl path).
        (as root)
        $ tar xzf openldap-2.x.xx.tar.gz
        $ cd openldap-2.x.xx
        $ ./configure --disable-ipv6 --disable-bdb --disable-hdb --enable-wrappers --enable-ldap --enable-perl
        $ make
        $ make install
  * At configure, you can choose options such as ipv6, bdb, wrappers, and others.
  * But '--enable-perl' and '--enable-ldap' options are very important.
  * On configure, your system's perl path is specified and built slapd binary use that.
  * You can access slapd and openldap config file as below.
        /usr/local/libexec/slapd
        /usr/local/etc/openldap/slapd.conf

### MySQL

Various MySQL packages are avaiable, and whada doesn't need any specific settings.
You can install mysqld in same host, or other network reachable host.

'whada' uses two databases ('whadaadmin' and 'whadasession'), so you may create a user for these databases.

    MySQL> CREATE USER 'whadauser'@'%' IDENTIFIED BY 'secret';
    MySQL> GRANT ALL ON whadaadmin.* TO 'whadauser'@'%';
    MySQL> GRANT ALL ON whadasession.* TO 'whadauser'@'%';
    MySQL> FLUSH PRIVILEGES;

### Whada

* Download 'whada' tarball and extract it, or clone directly
  * https://github.com/tagomoris/whada
  * as root user
* Install CPAN modules
  * For system perl (or root users perlbrew environment perl)
  * cpanm strongly recommended
        (as root)
        $ cd whada
        $ cpanm -n --installdeps .
  * For cpanm, see http://search.cpan.org/dist/App-cpanminus/
  * slapd cannot use extlib

## Setup whada

### Configuration file
Write configuration json file. whada uses 'config.json' file in whada root directory (ex: 'whada/'). See 'config.template.json'.

* 'load_path' section: list of library paths for your whada extension packages
  * 'load_path' section is for whada web admin page. slapd backend uses library path configuration on slapd.conf.
* 'auth_source' section: your LDAP server information
* 'storage' section: MySQL connection settings 

JSON syntax is very rigid. You should pay attention for comma at line end of array/hash's last item.

### Privilege initial setup
'bin/privmanage' is a utility for privilege add/remove operaitons on CLI. You must do initial setup by command below.

    $ bin/privmanage -i

If you want to permit all users for all privileges that doesn't be defined explicitly, set 'global_default_privilege' as 'allowed'. (But this setting is not recommended.)

    $ bin/privmanage -i allowed

And you should specify administrator user account of whada, then permit whada administrator privilege for him (yourself).

    $ bin/privmanage -u superman -a WHADA WHADA+ADMIN

Privileges are
* WHADA: permission for whada's admin web page access, without privilege modification
* WHADA+ADMIN: permission as whada administrator (all configuration changes are allowed with this)
* FOO: you can define any privileges formatted as /^[A-Z\+]+$/
* WHADA+ADMIN+XXX: permission as limited administrator, to create/drop/modify privileges XXX and XXX+ANY+OTHER+INFO

### Whada admin page

If you set LDAP configuration properly, you can show whada admin page via browser. Launch app.psgi.

    # plackup app.psgi

Access http://localhost:5000/ and input your account name and password. With any troubles, see /tmp/whada.admin.log .

For normal operations, you can run admin web app with daemonize tools such as daemontools, supervisord or any others.

### slapd configuration

For client authentication on LDAP protocol, slapd.conf configuration needed.

You should check original ldap server configuration, and setup two backend, perl-backend and ldap-backend in slapd.conf.

* Original ldap specifications:
  * server name: ldap.server.intranet
  * port: 389
  * suffix for your ldap domain: dc=ad,dc=yourcompany,dc=intranet
  * dn for bind: cn=Manager,cn=Users,dc=ad,dc=yourcompany,dc=intranet
  * password for bind: secret
  * search base cn: cn=Users,dc=ad,dc=yourcompany,dc=intranet
  * attribute name equals to account name: sAMAccountName
* Whada specifications:
  * suffix for your whada domain: dc=whada,dc=intranet
  * whada path: /root/whada
  * configuration file path: /root/whada/config.json
  * dn for bind: cn=binduser,dc=whada,dc=intranet
  * password for bind: whadaseret

In this case, you should configure slapd as below.

    ############## ldap backend #############
    database        ldap
    suffix          "dc=ad,dc=yourcompany,dc=intranet"
    uri             ldap://ldap.server.intranet/
    lastmod         off
    binddn          "cn=Manager,cn=Users,dc=ad,dc=yourcompany,dc=intranet"
    bindpw          secret
    
    chase-referrals no
    conn-ttl        15
    idle-timeout    5
    single-conn     yes
    
    ############## perl backend #############
    database        perl
    suffix          "dc=wada,dc=intranet"
    rootdn          "cn=binduser,dc=whada,dc=intranet"
    rootpw          whadasecret
    perlModulePath  /root/whada/lib
    perlModule      Whada::SlapdBackendHandler
    whadaConfigFile   /root/ldwhada/config.json
    whadaLogPath      /var/log/whada.slapd.log.%Y%m%d
    whadaSuffix       dc=wada,dc=intranet

And configure config.json as below.

    {
      "load_path":[
        "/root/whada/lib"
      ],
      "auth_source":{
        "type":"ldap",
        "host":"ldap.server.intranet",
        "binddn":"cn=Manager,cn=Users,dc=ad,dc=yourcompany,dc=intranet",
        "bindpassword":"secret",
        "base":"cn=Users,dc=ad,dc=yourcompany,dc=intranet",
        "attribute":"sAMAccountName"
      },
      "storage":{
        "type":"DB",
        "host":"localhost",
        "port":3306,
        "username":"whada",
        "password":"adahw"
      }
    }

In this environment, you can search/bind to this slapd in 2-ways.

* privilege as 'ou' in search base
  * search base: ou=FOO,dc=wada,dc=intranet
  * filter: (uid=superman) or (user=superman) or (sAMAccountName=superman)
* privilege as filter element
  * search base: dc=wada,dc=intranet
  * filter: (&(uid=superman)(privilege=FOO))

If 'superman' is allowed privilege 'FOO', 'search' query returns LDAP entry with dn, its suffix is 'dc=ad,dc=yourcompany,dc=intranet'. In fact, that entry is same with result that you query with 'dc=ad,dc=yourcompany,dc=intranet' directly.

## HOW TO USE

### ldapsearch

### Apache mod_authnz_ldap

for example:

    <Directory /var/www/html>
        Options +Indexes
        AllowOverride None

        Order deny,allow
        Deny from all
        Satisfy any

        AuthName "ldap perl backend auth"
        AuthType Basic
        AuthBasicProvider ldap
        AuthLDAPUrl "ldap://127.0.0.1:389/ou=FOO,dc=wada,dc=intranet?user?sub?(objectClass=*)"
        AuthLDAPBindDN "cn=binduser,dc=whada,dc=intranet"
        AuthLDAPBindPassword secretwhada
        Require valid-user
    </Directory>

### Perl/Ruby Code

* * * * *

## License

Copyright 2011 TAGOMORI Satoshi (tagomoris)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
