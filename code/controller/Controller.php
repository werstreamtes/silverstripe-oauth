<?php

namespace oauth\controller;

use SilverStripe\Control\HTTPRequest as Req;
use \oauth\model as Model;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Forms\CheckboxSetField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\Forms\FormAction;
use SilverStripe\Security\Security;

/**
 * OAuth Controller
 *
 * This controller provides the end points for the
 * OAuth process. That is, it provides the end point
 * for issuing tokens and for authenticating end
 * users.
 */
class Controller extends \SilverStripe\Control\Controller
{
    /**
     * Template that's used to render the pages.
     *
     * @var string
     */
    public static $template_main = 'Page';

    public static $template = 'BlankPage';

    private static $allowed_actions = [
        'authorise',
        'cancel',
        'runauth',
        'token',
        'AuthForm',
    ];

    public function Link($action = null)
    {
        return self::join_links('oauth', $action);
    }

    /**
     * Authorise a client.
     *
     * This method takes a client identifier, redirect URI,
     * response type (must be code) and list of scopes. Once
     * these have been validated, the end user is asked to
     * authorise the request application and accept the
     * requested scopes. The user interface for this is
     * handled by the runauth() method.
     */
    public function authorise(Req $req)
    {
        $session = $this->request->getSession();
        $session->clear('oauth');
        // If a state is provided, we need to return it with the token
        if ($req->requestVar('state')) {
            $session->set('oauth.state', $req->requestVar('state'));
        }

        // Check the client identifier
        $clientID = $req->requestVar('client_id');
        $client = Model\Client::get()->filter('Identifier', $clientID)->First();
        if (!$client || !$client->exists()) {
            return $this->httpError(400, 'Invalid client identifier');
        }
        $session->set('oauth.client', $client->ID);

        // Check the redirect URI
        $uri = $req->requestVar('redirect_uri');
        if (!$client->validRedirectURI($uri)) {
            return $this->httpError(400, 'Invalid redirect URI');
        }
        $session->set('oauth.return', $uri);
        if (!$uri) {
            $uri = $client->DefaultEndpoint;
        }

        // Check response type. Must be code.
        if ($req->requestVar('response_type') != 'code') {
            return $this->oauthError('unsupported_response_type', 'This OAuth server requires a code response_type.', null, $uri);
        }

        // Check passed scopes
        if (trim($req->requestVar('scope'))) {
            $values = explode(' ', $req->requestVar('scope'));
            $options = Model\Scope::get()->filter('Name', $values);
            if ($options->Count() != count($values)) {
                return $this->oauthError('invalid_scope', 'At least one of the scopes requested is invalid.', null, $uri);
            }
            $session->set('oauth.scope', trim($req->requestVar('scope')));
        } else {
            $session->set('oauth.scope', '');
        }

        // Either get the member to log in, or redirect straight to the run auth page.
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            // $message = sprintf('%s would like to be authorised to use your account. <a href="%s"><button>Cancel</button></a>', $client->Name, $this->Link('cancel'));
            // $session->set('Security.Message.message', $message);

            $BackURL = $this->Link('runauth');
            $redirectTarget = 'Security/login';
            // Check if the User specified a preference for Sign Up or Login:
            if ($req->requestVar('signup') == 'true') {
                $redirectTarget = 'registrieren/';
            }

            $session->set('BackURL', $BackURL);
            return $this->redirect($redirectTarget . '?BackURL=' . urlencode($BackURL));
        }
        return $this->redirect($this->Link('runauth'));
    }

    /**
     * User cancels the OAuth process
     *
     * Either throw a 400 if there's no valid return URI or
     * return an access_denied error to the client.
     */
    public function cancel()
    {
        $session = $this->request->getSession();
        $uri = $session->get('oauth.return');
        if (!$uri) {
            return $this->httpError(400, 'Invalid redirect URI');
        }
        return $this->oauthError('access_denied', 'The resource owner denied the authorisation request.', null, $uri);
    }

    /**
     * Run the actual end user authentication part of the process.
     *
     * This simply provides a page for the AuthForm to be rendered
     * in. Will use a Page object if SiteTree exists (the CMS module
     * is installed), otherwise just uses this Controller to render
     * the page.
     */
    public function runauth(Req $req)
    {
        $session = $req->getSession();
        // EMake Sure user is authenticated
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            $session->set('BackURL', $this->Link('runauth'));
            return $this->redirect('Security/login?BackURL=' . urlencode($this->Link('runauth')));
        }

        if (class_exists('SiteTree')) {
            $tmpPage = new \Page();
            $tmpPage->Title = 'Authorise';
            $tmpPage->URLSegment = 'oauth';
            // Disable ID-based caching  of the auth page by making it a random number
            $tmpPage->ID = -1 * rand(1, 10000000);

            $controller = new \PageController($tmpPage);
            $controller->setDataModel($this->model);
            $controller->init();
        } else {
            $controller = $this;
            $controller->Title = 'Authorise';
        }

        $client = Model\Client::get()->byID($session->get('oauth.client'));
        if (!$client || !$client->exists()) {
            return $this->httpError(400, 'Invalid client identifier');
        }

        if ($client->AutoAllow) {
            return $this->autoAllow();
        }

        $data = [
            'Form' => $this->AuthForm(),
            'Client' => $client
        ];

        $customisedController = $controller->customise($data);

        return $customisedController->renderWith(['Oauth_runauth', 'Oauth', $this->stat('template_main'), 'BlankPage']);
    }

    private function autoAllow()
    {
        $session = $this->request->getSession();
        // Get requested scopes, or defaults if none requested
        if ($scope = $session->get('oauth.scope')) {
            $values = explode(' ', $scope);
            $scope = Model\Scope::get()->filter('Name', $values);
        } else {
            $scope = Model\Scope::get()->filter('Default', 1);
        }

        $code = new Model\AuthCode;
        $code->RedirectURI = $session->get('oauth.return');
        $code->ClientID = $session->get('oauth.client');
        $code->MemberID = Security::getCurrentUser()->ID;
        $code->write();
        $code->Scopes()->addMany($scope);
        return $this->redirect($code->SendEndpoint());
    }


    /**
     * Validate a request token.
     *
     * Checks a request token against those that have been
     * issued. Requires the redirect URI provided when
     * requesting authentication to match exactly.
     *
     * If successful, returns an access token.
     */
    public function token(Req $req)
    {
        // Request MUST be over POST
        if (!$req->isPOST()) {
            return $this->oauthError('invalid_request', 'POST is required');
        }

        // We only support the authorization_code grant type
        if ($req->postVar('grant_type') != 'authorization_code') {
            return $this->oauthError('unsupported_grant_type', 'grant_type must be authorization_code');
        }

        // Check the supplied code against issued tokens
        $code = $req->postVar('code');
        $token = Model\AuthCode::get()->filter('Code', $code)->First();
        if (!$token || !$token->exists()) {
            return $this->oauthError('invalid_grant', 'Access code not found.');
        }
        // Check the token hasn't expired
        if (!$token->IsValid()) {
            return $this->oauthError('invalid_grant', 'Access code expired.');
        }

        // The redirect URI must match exactly what was provided.
        if ($token->RedirectURI != $req->postVar('redirect_uri')) {
            return $this->oauthError('invalid_grant', 'Invalid redirect URI.');
        }

        // Generate the response data
        $data = $this->authTokenService->generateAccessTokenData($token);

        // Delete the token
        $token->delete();

        // Respond with the data. Must be sent as JSON over UTF-8.
        $response = new HTTPResponse(json_encode($data), 200);
        $response->addHeader('Content-Type', 'application/json;charset=UTF-8');
        return $response;
    }

    /**
     * Authentication form
     *
     * This form is what lets the end user decide which scopes
     * to allow to the requesting client, as well as cancelling
     * the whole login process.
     */
    public function AuthForm()
    {
        $session = $this->request->getSession();
        // Get requested scopes, or defaults if none requested
        if ($scope = $session->get('oauth.scope')) {
            $values = explode(' ', $scope);
            $scope = Model\Scope::get()->filter('Name', $values);
        } else {
            $scope = Model\Scope::get()->filter('Default', 1);
        }
        // Remove all those that the end user has to allow
        $fields = new FieldList(
            $csf = new CheckboxSetField('Scopes', 'Allow scopes:', $scope, $scope)
        );
        $csf->setDisabledItems($scope->filter('CantDisallow', 1)->column('ID'));
        $actions = new FieldList(
            new FormAction('doAllow', 'Allow access'),
            new FormAction('cancel', 'Deny access')
        );
        return new Form($this, __FUNCTION__, $fields, $actions);
    }

    /**
     * Success handler for {@link AuthForm()}
     *
     * This method creates a one-time auth code that contains
     * the information needed for validating its use as well
     * as the scopes it allows. The end user is then sent back
     * to the client with this information as part of the request.
     */
    public function doAllow($data, $form)
    {
        $session = $this->request->getSession();
        $code = new Model\AuthCode;
        $code->RedirectURI = $session->get('oauth.return');
        $code->ClientID = $session->get('oauth.client');
        $code->MemberID = Security::getCurrentUser()->ID;
        $code->write();
        $form->saveInto($code);
        // Add in the requested scopes that can't be refused
        if ($scope = $session->get('oauth.scope')) {
            $values = explode(' ', $scope);
            $scope = Model\Scope::get()->filter('Name', $values);
        } else {
            $scope = Model\Scope::get()->filter('Default', 1);
        }
        $scope = $scope->filter('CantDisallow', 1);
        $code->Scopes()->addMany($scope);
        return $this->redirect($code->SendEndpoint());
    }

    /**
     * Helper function for returning an OAuth error
     * @throws HTTPResponse_Exception
     */
    protected function oauthError($code, $desc = null, $uri = null, $redirectTo = null)
    {
        $session = $this->request->getSession();
        $error = ['error' => $code];
        if ($desc) {
            $error['error_description'] = $desc;
        }
        if ($uri) {
            $error['error_uri'] = $uri;
        }
        if ($session->get('oauth.state')) {
            $error['state'] = $session->get('oauth.state');
        }
        $session->clear('oauth');
        if ($redirectTo) {
            $append = '?' . http_build_query($error);
            $link = self::join_links($redirectTo, $append);
            return $this->redirect($link);
        }
        $response = new HTTPResponse(json_encode($error, 0), 400);
        $response->addHeader('Content-Type', 'application/json;charset=UTF-8');
        throw new HTTPResponse_Exception($response);
    }


    /**
     * Redirect to the given URL. Do not use Silverstripe Redirect for custom Url Schemas
     *
     * @param string $url
     * @param int $code
     * @return HTTPResponse
     */
    public function redirect(string $url, int $code = 302): HTTPResponse
    {
        if(substr($url,0,13) == "http-x-wse://") {
            $response = new HTTPResponse();
            $this->setResponse($response->redirect($url, $code));
        } else {
            $response = parent::redirect($url, $code);
            $this->setResponse($response);
        }
        return $response;
    }

}
