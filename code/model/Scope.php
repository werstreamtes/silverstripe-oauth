<?php

namespace oauth\model;

use SilverStripe\ORM\DataObject;

/**
 * An OAuth scope
 *
 * Scopes are similar to permissions and are granted to
 * requesting clients. A scope can be set to default, so
 * a client is given it if it asks for none, and can't
 * disallow, so that if a client requests it, the end user
 * can't deny it.
 */
class Scope extends DataObject
{
    private static $db = [
        'Name' => 'Varchar',
        'Description' => 'Text',
        'Default' => 'Boolean',
        'CantDisallow' => 'Boolean',
    ];

    private static $singular_name = 'OAuth Scope';

    public function getTitle()
    {
        // Event handler for title, with an option to let it set its own title
        $eventResults = $this->extend('getTitle');
        // If there was a string returned, then return that
        if ($eventResults) {
            foreach ($eventResults as $result) {
                if ($result && is_string($result)) return $result;
            }
        }
        return "{$this->Description} ({$this->Name})";
    }
}
