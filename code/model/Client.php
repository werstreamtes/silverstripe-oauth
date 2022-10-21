<?php

namespace oauth\model;

/**
 * An OAuth client
 */
class Client extends \DataObject {
	public static $db = array(
		'Name' => 'Varchar',
		'Description' => 'Text',
		'Website' => 'Varchar(255)',
		'Identifier' => 'Varchar(128)',
		'DefaultEndpoint' => 'Varchar(1024)',
        'AutoAllow' => "Boolean"
	);

	public static $has_one = array(
		'Logo' => 'Image',
	);

	public static $has_many = array(
		'RedirectionURLs' => 'oauth\model\RedirectionURL',
		'AuthCodes' => 'oauth\model\AuthCode',
	);

	public static $indexes = array(
		'Identifier' => array(
			'type' => 'unique',
			'value' => 'Identifier'
		)
	);

	public static $singular_name = 'OAuth Client';

	public function getCMSFields() {
		$fields = parent::getCMSFields();
		$field = $fields->dataFieldByName('Identifier')->performReadonlyTransformation();
		$fields->replaceField('Identifier', $field);
		$fields->removeByName('AuthCodes');
		return $fields;
	}

	public function onBeforeWrite() {
		parent::onBeforeWrite();
		if(!$this->Identifier) {
			$generator = new \RandomGenerator();
			do {
				$iden = $generator->generateHash();
			} while(self::get()->filter('Identifier', $iden)->Count() > 0);
			$this->Identifier = $iden;
		}
	}

	/**
	 * Validate a given redirect URI against the URLs provided for this client.
	 *
	 * This matches the method laid out in the OAuth 2 spec.
	 */
	public function validRedirectURI($uri = null) {
		if(!$uri) {
			$uri = $this->DefaultEndpoint;
		}
		if(!$uri) {
			return false;
		}
		$endpoints = $this->RedirectionURLs();
		if(!$endpoints->Count()) {
			return true;
		}
		$parts = parse_url($uri);
		foreach($endpoints as $Url) {
			$e = $Url->Endpoint;
			$e = parse_url($e);
			if(!$e) {
				$e = array('path' => $Url->Endpoint);
			}
			foreach(array('scheme', 'host', 'port') as $check) {
				if(!isset($e[$check])) {
					continue;
				}
				if(!isset($parts[$check])) {
					continue 2;
				}
				if(strtolower($e[$check]) !== strtolower($parts[$check])) {
					continue 2;
				}
			}
			if(isset($e['query'])) {
				if(!isset($parts['query'])) {
					continue;
				}
				parse_str($e['query'], $required);
				parse_str($parts['query'], $check);
				if(count(array_intersect_key($required, $check)) != count($required)) {
					continue;
				} 
			}
			if(empty($e['path'])) {
				return true;
			}
			if(isset($e['host'])) {
				if(empty($parts['path'])) {
					continue;
				}
				if(strpos($parts['path'], $e['path']) === 0) {
					return true;
				}
			} else {
				if(strpos($parts['host'] . $parts['path'], $e['path']) === 0) {
					return true;
				}
			}
		}
		return false;
	}
}
