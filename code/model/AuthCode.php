<?php

namespace oauth\model;

use oauth\controller\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\RandomGenerator;

/**
 * A temporary authentication code, returned to the client via a browser redirect by the end user.
 */
class AuthCode extends DataObject
{
    private static $db = [
        'Code' => 'Varchar(128)',
        'RedirectURI' => 'Varchar(1024)',
    ];

    private static $has_one = [
        'Client' => 'oauth\model\Client',
        'Member' => 'SilverStripe\Security\Member',
    ];

    private static $many_many = [
        'Scopes' => 'oauth\model\Scope',
    ];

    private static $indexes = [
        'Code' => true,
        [
            'type' => 'unique',
            'columns' => ['Code']
        ]
    ];

    private static $table_name = 'OAuth_AuthCode';

    private static $singular_name = 'OAuth Auth Code';

    /**
     * strtotime() formatted string for how long tokens should be valid for
     */
    private static $timeout = '10 minutes';

    public function IsValid()
    {
        return strtotime('+' . static::$timeout, strtotime($this->Created)) >= time();
    }

    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if (!$this->Code) {
            $generator = new RandomGenerator();
            do {
                $code = $generator->randomToken();
            } while (self::get()->filter('Code', $code)->Count() > 0);
            $this->Code = $code;
        }
    }

    /**
     * The URL to send the end user to, including token and scope information.
     */
    public function SendEndpoint()
    {

        $request = Injector::inst()->get(HTTPRequest::class);
        $session = $request->getSession();

        $url = $this->RedirectURI ?: $this->Client()->DefaultEndpoint;
        $parts = ['code' => $this->Code];
        if ($session->get('oauth.state')) {
            $parts['state'] = $session->get('oauth.state');
        }
        $parts['scope'] = implode(' ', $this->Scopes()->Column('Name'));
        $append = '?' . http_build_query($parts);
        return Controller::join_links($url, $append);
    }
}
