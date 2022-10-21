<?php

namespace oauth\model;

use SilverStripe\ORM\DataObject;

/**
 * An authentication token, linked to a particular client and member
 */
class AuthToken extends DataObject
{
    private static $db = [
        'Expires' => 'Datetime',
        'Code' => 'Varchar(255)'
    ];

    private static $has_one = [
        'Client' => 'oauth\model\Client',
        'Member' => 'SilverStripe\Security\Member',
    ];

    private static $many_many = [
        'Scopes' => 'oauth\model\Scope'
    ];

    public function Expired()
    {
        return $this->authTokenService->tokensExpire() && $this->dbObject('Expires')->InPast();
    }
}
