<?php

namespace oauth\service;

use oauth\model as m;
use oauth\model\AuthCode;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;

class Bearer implements Service
{
    /**
     * The list of characters a token can be made from
     */
    const TOKENCHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-._~+/';

    /**
     * The detected token for the current request
     */
    protected $token = null;

    /**
     * Generate access token data and create the {@link oauth\model\AuthToken}.
     *
     * Data generated is the access token itself, when it expires and the list
     * of scopes. Uses oauth\service\Bearer::$token_life as the number of seconds
     * the token is valid for. The length of the token is determined by
     * oauth\service\Bearer::$token_length
     */
    public function generateAccessTokenData(AuthCode $code)
    {
        $token_length = Config::inst()->get('oauth\service\Bearer', 'token_length');
        $numChars = strlen(self::TOKENCHARS);
        $tokens = self::TOKENCHARS;
        do {
            $token = '';
            for ($i = 0; $i < $token_length; ++$i) {
                $token .= $tokens[mt_rand(1, $numChars) - 1];
            }
        } while (m\AuthToken::get()->filter('Code', $token)->Count() > 0);
        $t = new m\AuthToken;
        $t->Code = $token;
        $t->Expires = time() + (int)Config::inst()->get('oauth\service\Bearer', 'token_life');
        $t->ClientID = $code->ClientID;
        $t->MemberID = $code->MemberID;
        $t->write();
        $t->Scopes()->setByIDList($code->Scopes()->getIDList());
        $data = [
            'access_token' => $t->Code,
            'expires_in' => (int)Config::inst()->get('oauth\service\Bearer', 'token_life'),
            'token_type' => 'Bearer',
            'scope' => implode(' ', $t->Scopes()->Column('Name'))
        ];
        if ($data['expires_in'] < 0) {
            unset($data['expires_in']);
        }
        return $data;
    }

    /**
     * Authenticate a request against the given scopes.
     *
     * Requires that the getallheaders() function exists to authenticate against
     * the Authorization header.
     */
    public function authRequest(HTTPRequest $req, array $scopes)
    {
        // If we can, get all the headers and check the Authorixation one
        if (function_exists('getallheaders') && ($headers = getallheaders())) {
            $headers = array_combine(
                array_map('strtolower', array_keys($headers)),
                array_values($headers)
            );
            $auth = $headers['authorization'] ?? null;
            if ($auth && substr($auth, 0, 7) == 'Bearer ') {
                list(, $code) = explode(' ', $auth, 2);
                $this->token = m\AuthToken::get()->filter('Code', $code)->First();
                if ($this->token && $this->token->exists()) {
                    if ($this->token->Expired()) {
                        return $this->authError(401, 'invalid_token', 'The token has expired.');
                    } elseif ($req->requestVar('access_token')) {
                        return $this->authError(400, 'invalid_request', 'Multiple methods used.');
                    } elseif ($scopes && $this->token->Scopes()->filter('Name', $scopes)->Count() != count($scopes)) {
                        return $this->authError(403, 'insufficient_scope');
                    } else {
                        return $this->token;
                    }
                } else {
                    return $this->authError(401, 'invalid_token', 'The token does not exist.');
                }
            } elseif ($auth) {
                return $this->authError(400, 'invalid_request', 'Unsupported Authorization header.');
            }
        }
        // If oauth\service\Bearer::$allow_form_body is set, check post vars for a token
        if (Config::inst()->get('oauth\service\Bearer', 'allow_form_body') && $code = $req->postVar('access_token')) {
            $this->token = m\AuthToken::get()->filter('Code', $code)->First();
            if ($this->token && $this->token->exists()) {
                if ($this->token->Expired()) {
                    return $this->authError(401, 'invalid_token', 'The token has expired.');
                } elseif ($req->getVar('access_token')) {
                    return $this->authError(400, 'invalid_request', 'Multiple methods used.');
                } elseif ($scopes && $this->token->Scopes()->filter('Name', $scopes)->Count() != count($scopes)) {
                    return $this->authError(403, 'insufficient_scope');
                } else {
                    return $this->token;
                }
            } else {
                return $this->authError(401, 'invalid_token', 'The token does not exist.');
            }
        }
        // If oauth\service\Bearer::$allow_url_param is set, check get vars for a token
        if (Config::inst()->get('oauth\service\Bearer', 'allow_url_param') && $code = $req->getVar('access_token')) {
            $this->token = m\AuthToken::get()->filter('Code', $code)->First();
            if ($this->token && $this->token->exists()) {
                if ($this->token->Expired()) {
                    return $this->authError(401, 'invalid_token', 'The token has expired.');
                } elseif ($req->postVar('access_token')) {
                    return $this->authError(400, 'invalid_request', 'Multiple methods used.');
                } elseif ($scopes && $this->token->Scopes()->filter('Name', $scopes)->Count() != count($scopes)) {
                    return $this->authError(403, 'insufficient_scope');
                } else {
                    return $this->token;
                }
            } else {
                return $this->authError(401, 'invalid_token', 'The token does not exist.');
            }
        }
        return $this->authError();
    }

    /**
     * Check if the token in the request has the request scope, optionally throwing an error
     *
     * If a token hasn't been loaded, this just calls {@link authRequest()}, otherwise it does
     * a straight forward check.
     */
    public function currentTokenHasScopes(HTTPRequest $request, $scopes, $error = false)
    {
        if (!$this->token) {
            try {
                $this->authRequest($request, $scopes);

                /** @var IdentityStore $identityStore */
                $identityStore = Injector::inst()->get(IdentityStore::class);
                $identityStore->logIn($this->token->Member(), true, $request);

                return true;
            } catch (HTTPResponse_Exception $e) {
                if ($error) {
                    throw $e;
                } else {
                    return false;
                }
            }
        }
        if ($this->token->Scopes()->filter('Name', $scopes)->Count() != count($scopes)) {
            if ($error) {
                return $this->authError(403, 'insufficient_scope');
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether or not tokens should expire.
     *
     * @return boolean
     */
    public function tokensExpire()
    {
        return Config::inst()->get('oauth\service\Bearer', 'token_life') >= 0;
    }

    /**
     * @throws HTTPResponse_Exception
     */
    public function httpError($errorCode, $errorMessage = null)
    {
        if ($this->token) {
            switch ($errorCode) {
                case 400:
                    return $this->authError(400, 'invalid_request', $errorMessage);
                case 401:
                    return $this->authError(401, 'invalid_token', $errorMessage);
                case 403:
                    return $this->authError(403, 'insufficient_scope', $errorMessage);
            }
        }
    }

    /**
     * Helper method for throwing OAuth errors
     * @throws HTTPResponse_Exception
     */
    protected function authError($code = 401, $error = null, $description = null, $uri = null)
    {
        $response = new HTTPResponse(null, $code);
        $header = 'Bearer';
        if ($error) {
            $header .= " error=\"$error\"";
            if ($description) {
                $header .= " error_description=\"$description\"";
            }
            if ($uri) {
                $header .= " error_uri=\"$uri\"";
            }
        }
        $response->addHeader('WWW-Authenticate', $header);
        throw new HTTPResponse_Exception($response);
    }
}
