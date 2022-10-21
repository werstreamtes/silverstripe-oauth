<?php

namespace oauth\model;

/**
 * An authentication token, linked to a particular client and member
 */
class AuthToken extends \DataObject {
	public static $db = array(
		'Expires' => 'Datetime',
		'Code' => 'Varchar(255)',
	);

	public static $has_one = array(
		'Client' => 'oauth\model\Client',
		'Member' => 'Member',
	);

	public static $many_many = array(
		'Scopes' => 'oauth\model\Scope',
	);

	public function Expired() {
		return $this->authTokenService->tokensExpire() && $this->dbObject('Expires')->InPast();
	}
}
