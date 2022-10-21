<?php

namespace oauth\model;

/**
 * A temporary authentication code, returned to the client via a browser redirect by the end user.
 */
class AuthCode extends \DataObject {
	public static $db = array(
		'Code' => 'Varchar(128)',
		'RedirectURI' => 'Varchar(1024)',
	);

	public static $has_one = array(
		'Client' => 'oauth\model\Client',
		'Member' => 'Member',
	);

	public static $many_many = array(
		'Scopes' => 'oauth\model\Scope',
	);

	public static $indexes = array(
		'Code' => array(
			'type' => 'unique',
			'value' => 'Code'
		)
	);

	public static $singular_name = 'OAuth Auth Code';

	/**
	 * strtotime() formatted string for how long tokens should be valid for
	 */
	public static $timeout = '10 minutes';

	public function IsValid() {
		return strtotime('+' . static::$timeout, strtotime($this->Created)) >= time();
	}

	public function onBeforeWrite() {
		parent::onBeforeWrite();
		if(!$this->Code) {
			$generator = new \RandomGenerator();
			do {
				$code = $generator->generateHash();
			} while(self::get()->filter('Code', $code)->Count() > 0);
			$this->Code = $code;
		}
	}

	/**
	 * The URL to send the end user to, including token and scope information.
	 */
	public function SendEndpoint() {
		$url = $this->RedirectURI ?: $this->Client()->DefaultEndpoint;
		$parts = array('code' => $this->Code);
		if(\Session::get('oauth.state')) {
			$parts['state'] = \Session::get('oauth.state');
		}
		$parts['scope'] = implode(' ', $this->Scopes()->Column('Name'));
		$append = '?' . http_build_query($parts);
		return \Controller::join_links($url, $append);
	}
}
