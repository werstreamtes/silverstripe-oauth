<?php

namespace oauth\controller;

use SilverStripe\Admin\ModelAdmin;

/**
 * ModelAdmin instance for managing OAuth clients and scopes
 */
class Admin extends ModelAdmin
{

    private static $managed_models = [
        'oauth\model\Client',
        'oauth\model\Scope',
    ];

    private static $url_segment = 'oauth';
    private static $menu_title = 'OAuth';

}
