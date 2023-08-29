How to use RemoteUserSSL module
===============================

Thanks to Michal Prochazka, <michalp@ics.muni.cz> who developed RemoteUserSSL
module which was used as a basic for this module.

The module is just getting result of the SSL authentication done by NGINX
web server. Therefore the module doesn't need to cope with any unsuccessful
states of login process. NGINX will ensure that the user is properly
authenticated before he/she reach this module. Module then just extract
user identifier and pass it additional processing.

NGINX configuration
--------------------
```
server {
    ssl_verify_client optional_no_ca;
    ...

    location ^~ /saml {
        if ($ssl_access != 1) {
            return 403;
        }
        ...

        fastcgi_param SSL_CLIENT_SUBJECT_DN  $ssl_client_s_dn;
    }
}

map $ssl_client_i_dn $ssl_access {
    default 0;
    "~^CN=TERENA Personal CA 3,O=.+,C=NL$" 1;
    "~^CN=GEANT Personal CA 4,O=.+,C=NL$" 1;
    "~^GEANT Personal ECC CA 4,O=.+,C=NL" 1;
}
```
Module configuration
--------------------

The first thing you need to do is to enable the module:
```
config.php:
    'module.enable' => [
        ...
        'remoteuserssl' => true,
    ],
```
Then you must add it as an authentication source. Here is an
example authsources.php entry:

    'RemoteUserSSL' => array(
        'authRemoteUserSSL:RemoteUserSSL',
    ),
