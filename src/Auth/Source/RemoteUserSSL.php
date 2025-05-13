<?php

namespace SimpleSAML\Module\remoteuserssl\Auth\Source;

use SimpleSAML\Module\ldap\ConfigHelper;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Error\ErrorCodes;
use SimpleSAML\Logger;

/**
 * Getting user's identity either from SSL_CLIENT_SUBJECT_DN. The code of the module has been inspired
 * by module remoteUserSSL from Michal Prochazka, <michalp@ics.muni.cz>.
 *
 * @author Martin van Es, <martin.vanes@surf.nl>
 *
 * @package SimpleSAMLphp
 */
class RemoteUserSSL extends Auth\Source
{

    /**
     * Constructor for this authentication source.
     *
     * @param array $info Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        return;
    }

    /**
     * Get SSL_CLIENT_SUBJECT_DN
     *
     * This function just gets value from SSL_CLIENT_SUBJECT_DN. If it is
     * filled, then it let user in.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        assert(is_array($state));

        /* The new NGINX way */
        $raw_cert = $_SERVER['SSL_CLIENT_RAW_CERT'];
        $parsed_cert = openssl_x509_parse($raw_cert);
        $sho = "surfstar-idp.lab.surf.nl";
        $mail = @$parsed_cert['subject']['emailAddress'];
        if (!$mail) {
            $san = @$parsed_cert['extensions']['subjectAltName'];
            $san_array = array_map('trim', explode(",", $san));
            foreach ($san_array as $v) {
                $v_array = array_map('trim', explode(":", $v));
                if ($v_array[0] == 'email') {
                    $mail = $v_array[1];
                }
            }
        }
        $uid = str_replace("@", "_", $mail);
        $uid_hash = hash("sha256", $uid);
        $subject_id = "$uid_hash@$sho";
        $cn = @$parsed_cert['subject']['CN'];
        $cn_array = explode(" ", $cn);
        # filter away all elements from $cn_array that contain a @ character
        # because the Geant Research and Education Trust CA generates CNs like "Pietje Puk piet001@surf.nl"
        $cn_array = array_filter($cn_array, function ($v) {
            return strpos($v, '@') === false;
        });
        $cn = implode(" ", $cn_array);
        $givenname = $cn_array[0];
        $sn = implode(" ", array_splice($cn_array, 1));

        $attributes = array(
            'urn:mace:terena.org:attribute-def:schacHomeOrganization' => [$sho],
            'urn:mace:dir:attribute-def:uid' => [$uid],
            'urn:oasis:names:tc:SAML:attribute:subject-id' => [$subject_id],
            'urn:mace:dir:attribute-def:mail' => [$mail],
            'urn:mace:dir:attribute-def:cn' => [$cn],
            'urn:mace:dir:attribute-def:displayName' => [$cn],
            'urn:mace:dir:attribute-def:givenName' => [$givenname],
            'urn:mace:dir:attribute-def:sn' => [$sn],
            'urn:mace:dir:attribute-def:eduPersonPrincipalName' => ["$uid@$sho"],
            'urn:mace:dir:attribute-def:eduPersonAffiliation' => ["member", "employee"],
            'urn:mace:dir:attribute-def:eduPersonScopedAffiliation' => ["member@$sho", "employee@$sho"],
        );
        $state['Attributes'] = $attributes;
        $this->authSuccesful($state);

        assert(false); // should never be reached
    }

    /**
     * Finish a successful authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations after login.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authSuccesful(&$state)
    {
        Auth\Source::completeAuth($state);

        assert(false); // should never be reached
    }

    /**
     * Finish a failed authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations on failure.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authFailed(&$state)
    {
        $config = Configuration::getInstance();

        $t = new Template($config, 'remoteuserssl:RemoteUserSSLerror.php');
        $t->data['loginurl'] = HTTP::getSelfURL();
        if (isset($state['remoteUserSSL.error'])) {
            $t->data['errorcode'] = $state['remoteUserSSL.error'];
        }
        $t->data['errorcodes'] = ErrorCodes::getAllErrorCodeMessages();

        $t->show();

        exit();
    }

    private function parseLdapDn($dn)
    {
        $parsr = ldap_explode_dn($dn, 0);
        $out = array();
        foreach ($parsr as $key => $value) {
            if (FALSE !== strstr($value, '=')) {
                list($prefix, $data) = explode("=", $value);
                print("$data\n");
                $data = preg_replace_callback("/\\\\([0-9A-Fa-f]{2})/", function ($m) {
                    return chr(hexdec($m[0]));
                }, $data);
                if (isset($current_prefix) && $prefix == $current_prefix) {
                    $out[$prefix][] = $data;
                } else {
                    $current_prefix = $prefix;
                    $out[$prefix][] = $data;
                }
            }
        }
        return $out;
    }
}
