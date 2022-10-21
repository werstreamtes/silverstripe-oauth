<?php

namespace oauth\model;

/**
 * A redirection URL
 */
class RedirectionURL extends \DataObject {
	public static $db = array(
		'Endpoint' => 'Varchar(1024)',
	);

	public static $has_one = array(
		'Client' => 'oauth\model\Client',
	);

	public static $singular_name = 'OAuth Client Redirection URL';

	public function getCMSFields() {
		$fields = parent::getCMSFields();
		$fields->removeByName('ClientID');
		return $fields;
	}

	public function getTitle() {
		return $this->Endpoint;
	}
}
