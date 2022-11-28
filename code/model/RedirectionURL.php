<?php

namespace oauth\model;

use SilverStripe\ORM\DataObject;

/**
 * A redirection URL
 */
class RedirectionURL extends DataObject
{
    private static $db = [
        'Endpoint' => 'Varchar(1024)',
    ];

    private static $has_one = [
        'Client' => 'oauth\model\Client',
    ];

    private static $table_name = 'OAuth_RedirectionURL';

    private static $singular_name = 'OAuth Client Redirection URL';

    public function getCMSFields()
    {
        $fields = parent::getCMSFields();
        $fields->removeByName('ClientID');
        return $fields;
    }

    public function getTitle()
    {
        return $this->Endpoint;
    }
}
