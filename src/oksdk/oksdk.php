<?php

namespace oksdk;


class oksdk
{
    /**
     * Application id
     * @var string
     */
    private $appId;

    /**
     * Public application key
     * @var string
     */
    private $publicKey;

    /**
     * Secret application key
     * @var string
     */
    private $secret;

    /**
     * Saved access and refresh tokens
     * @var array
     */
    private $tokens = array();

    /**
     * @param string $appId Your application id
     * @param string $publicKey Your application public key
     * @param string $secret Your application secret
     */
    public function __construct($appId, $publicKey, $secret)
    {
        $this->appId = $appId;
        $this->publicKey = $publicKey;
        $this->secret = $secret;
    }

    /**
     * Generates odnoklassniki authorization URL, that you use for
     * redirect user
     *
     * @param string $redirectUri Your application id
     * @param array $scope requested permissions, by default used
     * only VALUABLE_ACCESS permission
     * @return string generated url
     */
    public function getAuthUrl($redirectUri, $scope = array('VALUABLE_ACCESS'))
    {
        $params = array(
            'client_id' => $this->appId,
            'response_type' => 'code',
            'redirect_uri' => $redirectUri
        );

        if (!empty($scope)) {
            $params['scope'] = implode(';', $scope);
        }

        $url = 'http://www.odnoklassniki.ru/oauth/authorize';

        return $url . '?' . http_build_query($params);
    }

    /**
     * Send request to odnoklassniki API, and get access and refresh tokens
     *
     * @param string $code auth code from GET
     * @param string $redirectUri the same $redirectUri, that was sended in getAuthUrl()
     * @throws \Exception on API or request error
     */
    private function getTokens($code, $redirectUri)
    {
        $curl = curl_init('http://api.odnoklassniki.ru/oauth/token.do');

        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query(array(
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'grant_type' => 'authorization_code',
            'client_id' => $this->appId,
            'client_secret' => $this->secret
        )));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

        $s = curl_exec($curl);
        curl_close($curl);

        $response = json_decode($s, true);

        if (!$response) {
            throw new \Exception('Odnoklassniki API error');
        }

        if (isset($response['error']) && $response['error']) {
            throw new \Exception($response['error']);
        }

        $this->tokens['accessToken'] = $response['access_token'];
        $this->tokens['refreshToken'] = $response['refresh_token'];
    }

    /**
     * Update access token by refresh token
     *
     * @param string $refreshToken received refresh token
     * @throws \Exception on API or request error
     */
    public function refreshAccessToken($refreshToken)
    {
        $curl = curl_init('http://api.odnoklassniki.ru/oauth/token.do');

        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query(array(
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
            'client_id' => $this->appId,
            'client_secret' => $this->secret
        )));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

        $s = curl_exec($curl);
        curl_close($curl);

        $response = json_decode($s, true);

        if (!$response || !isset($response['access_token'])) {
            throw new \Exception('Odnoklassniki API error');
        }

        $this->tokens['accessToken'] = $response['access_token'];
    }

    /**
     * Send request to odnoklassniki API, and get access token
     *
     * @param string $code auth code from GET
     * @param string $redirectUri the same $redirectUri, that was sended in getAuthUrl()
     * @return string access token
     */
    public function getAccessToken($code, $redirectUri)
    {
        if (!$this->tokens) {
            $this->getTokens($code, $redirectUri);
        }

        return $this->tokens['accessToken'];

    }

    /**
     * Send request to odnoklassniki API, and get refresh token
     *
     * @param string $code auth code from GET
     * @param string $redirectUri the same $redirectUri, that was sended in getAuthUrl()
     * @return string refresh token
     */
    public function getRefreshToken($code, $redirectUri)
    {
        if (!$this->tokens) {
            $this->getTokens($code, $redirectUri);
        }

        return $this->tokens['refreshToken'];
    }

    /**
     * Call odnoklassniki API method
     *
     * @param string $method method to call
     * @param array $params parameters for called method
     * @return mixed odnoklassniki response
     * @throws \Exception on API or request error
     */
    public function api($method, $params = array())
    {
        if (empty($this->tokens) || isset($this->tokens['accessToken'])) {
            throw new \Exception('Access token not defined');
        }

        $params['application_key'] = $this->publicKey;
        $params['method'] = $method;
        $params['format'] = 'json';
        $params['sig'] = $this->sign($params, $this->tokens['accessToken']);
        $params['access_token'] = $this->tokens['accessToken'];

        $curl = curl_init('http://api.odnoklassniki.ru/fb.do?' . http_build_query($params));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $response = curl_exec($curl);

        if (!$response = json_decode($response)) {
            throw new \Exception('Odnoklassniki API error');
        }

        if (!empty($response->error_code) && !empty($response->error_msg)) {
            throw new \Exception($response->error_msg, $response->error_code);
        }

        return $response;
    }

    /**
     * Generate request sign by request parameters
     *
     * @param array $params parameters for called method
     * @param array $accessToken received access token
     * @return string generated sign
     */
    private function sign($params, $accessToken)
    {
        $sign = '';
        ksort($params);
        foreach ($params as $key => $value) {
            if ('sig' == $key || 'resig' == $key) {
                continue;
            }
            $sign .= $key . '=' . $value;
        }

        $sign .= md5($accessToken . $this->secret);
        return md5($sign);
    }

} 