<?php

namespace WSE\OAuth;

use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;

/**
 * Extension class that can be attached to a controller to show that that controller requires OAuth
 *
 * Not providing any arguments to the constructor only requires
 * that this controller is accessed using OAuth. To not have any
 * checks done everywhere, but to still add the extension to a
 * controller, pass false to the constructor.
 *
 * To require that the OAuth request token has certain scopes before
 * allowing it to access the controller, pass the name of the scopes
 * as either an array or list of strings to the constructor.
 */
class RequireOAuth extends Extension
{
    protected $scopes;
    protected $checkOnInit = true;

    /**
     * Constructor. For use, see the class docblock.
     */
    public function __construct($scopes = null)
    {
        if ($scopes && !is_array($scopes)) {
            $scopes = func_get_args();
        } elseif ($scopes === false) {
            $this->checkOnInit = false;
        }
        $this->scopes = $scopes;

        parent::__construct();
    }

    /**
     * If we've been asked to check on init, check for a valid request and log the member in.
     */
    public function onBeforeInit()
    {
        if ($this->checkOnInit) {
            try {
                $token = $this->authTokenService->authRequest($this->owner->getRequest(), $this->scopes);
                
                /** @var IdentityStore $identityStore */
                $identityStore = Injector::inst()->get(IdentityStore::class);
                $identityStore->logIn($token->Member(), true, $this->owner->getRequest());

            } catch (HTTPResponse_Exception $e) {
                $this->owner->popCurrent();
                throw $e;
            }
        }
    }

    /**
     * Require that the OAuth request has the given scopes.
     *
     * Use this method if not having those scopes should result in an OAuth error,
     * i.e. as a check in {@link RequestHandler::$allowed_actions}
     */
    public function requireScopes($scopes)
    {
        if (!is_array($scopes)) {
            $scopes = func_get_args();
        }
        return $this->authTokenService->currentTokenHasScopes($this->owner->getRequest(), $scopes, true);
    }

    /**
     * Check if the OAuth request has the given scopes.
     *
     * Use this method if not having those scopes isn't fatal, i.e. to provide
     * extra functionality if those scopes are present.
     */
    public function hasScopes($scopes)
    {
        if (!is_array($scopes)) {
            $scopes = func_get_args();
        }
        return $this->authTokenService->currentTokenHasScopes($this->owner->getRequest(), $scopes);
    }

    public function httpError($errorCode, $errorMessage = null)
    {
        if (method_exists($this->authTokenService, 'httpError')) {
            $this->authTokenService->httpError($errorCode, $errorMessage);
        }
    }
}
