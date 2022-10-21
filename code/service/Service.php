<?php

namespace oauth\service;

use oauth\model\AuthCode;
use SilverStripe\Control\HTTPRequest;

/**
 * The interface for an OAuth service
 *
 * A service generates access token data, authenticates
 * requests and checks if the current request has the
 * given scopes.
 */
interface Service
{
    /**
     * Authenticates a request, ensuring it has the given scopes.
     */
    public function authRequest(HTTPRequest $req, array $scopes);

    /**
     * Generate the needed access token data for the given code. Should
     * also create the {@link oauth\model\AuthToken}.
     */
    public function generateAccessTokenData(AuthCode $code);

    /**
     * Check if the token in the given request has the given scopes,
     * optionally throwing an error.
     */
    public function currentTokenHasScopes(HTTPRequest $request, $scopes, $error = false);

    /**
     * Whether or not tokens should expire.
     *
     * @return boolean
     */
    public function tokensExpire();
}
