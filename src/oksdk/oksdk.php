<?php

namespace oksdk;


class oksdk
{
    private $appId;
    private $publicKey;
    private $secret;
    private $tokens;

    public function __construct($appId, $publicKey, $secret)
    {
        $this->appId = $appId;
        $this->publicKey = $publicKey;
        $this->secret = $secret;
    }

    public function getAuthUrl($redirectUri, $scope = null)
    {
        $params = array(
            'client_id' => $this->appId,
            'response_type' => 'code',
            'redirect_uri' => $redirectUri
        );

        if (!empty($scope)) {
            $params['scope'] = $scope;
        }

        $url = 'http://www.odnoklassniki.ru/oauth/authorize';

        return $url . '?' . http_build_query($params);
    }

    private function getTokens($code, $redirect_uri)
    {
        $curl = curl_init('http://api.odnoklassniki.ru/oauth/token.do');

        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, array(
            'code' => $code,
            'redirect_uri' => urlencode($redirect_uri),
            'grant_type' => 'authorization_code',
            'client_id' => $this->appId,
            'client_secret' => $this->secret
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-type: application/x-www-form-urlencoded'));

        $s = curl_exec($curl);
        curl_close($curl);

        $response = json_decode($s, true);

        if (!($responseJSON = json_decode($response))) {
            throw new \Exception('Odnoklassniki API error');
        }

        $this->tokens = $response;
    }

    public function getNewAccessToken($refreshToken)
    {
        $curl = curl_init('http://api.odnoklassniki.ru/oauth/token.do');

        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, array(
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
            'client_id' => $this->appId,
            'client_secret' => $this->secret
        ));
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-type: application/x-www-form-urlencoded'));

        $s = curl_exec($curl);
        curl_close($curl);

        $response = json_decode($s, true);

        if (!($responseJSON = json_decode($response))) {
            throw new \Exception('Odnoklassniki API error');
        }

        // @todo проверить!
        return $response['access_token'];
    }

    public function getAccessToken($code, $redirect_uri)
    {
        if (!$this->tokens) {
            $this->getTokens($code, $redirect_uri);
        }

        return $this->tokens['access_token'];

    }

    public function getRefreshToken($code, $redirect_uri)
    {
        if (!$this->tokens) {
            $this->getTokens($code, $redirect_uri);
        }

        return $this->tokens['refresh_token'];
    }

    public function api($method, $accessToken, $params = array())
    {
        $params['application_key'] = $this->publicKey;
        $params['method'] = $method;
        $params['format'] = 'json';
        $params['sig'] = $this->sign($params, $accessToken);
        $params['access_token'] = $accessToken;

        $curl = curl_init('http://api.odnoklassniki.ru/fb.do?' . http_build_query($params));
        $response = curl_exec($curl);

        if (!$response = json_decode($response)) {
            throw new \Exception('Odnoklassniki API error');
        }

        if (!empty($response->error_code) && !empty($response->error_msg)) {
            throw new \Exception($response->error_msg, $response->error_code);
        }

        return $response;
    }

    public function sign($params, $accessToken)
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