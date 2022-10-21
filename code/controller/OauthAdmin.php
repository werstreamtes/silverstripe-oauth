<?php

namespace oauth\controller;

/**
 * ModelAdmin instance for managing OAuth clients and scopes
 */
class Admin extends \ModelAdmin {
	private static $managed_models = array(
		'oauth\model\Client',
		'oauth\model\Scope',
	);

    private static $url_segment = 'oauth';

	private static $menu_title = 'OAuth';
    private static $menu_icon = 'mysite/images/icons/key.png';
}
