<?php

trait UnifiAPI {
    private function Request($ip, $path, $cookie, $csrfToken = '', $post = null, $verb = 'POST') {
        $url = "https://" . $ip . $path;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        if($post) {
            if($verb === 'POST') {
                curl_setopt($ch, CURLOPT_POST, 1);
            } else {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $verb);
            }
        }
        $header = array('Cookie: '.$cookie, 'Accept: application/json');
        if($csrfToken) {
            $header[] = 'x-csrf-token: '. $token;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        if($post) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $result = curl_exec($ch);
        curl_close($ch);

        $this->SendDebug('Request', 'URL: ' . $url . "| Cookie: " . $cookie, 0);

        return @json_decode($result, true);
    }

    private function Login($ip, $username, $password) {
        $url = "https://" . $ip . "/api/auth/login";

        $headers = [];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function( $curl, $header_line ) use (&$headers) {
            $idx = strpos($header_line,':');
            if($idx >= 1) {
                $name = substr($header_line, 0, $idx);
                $value = trim(substr($header_line, $idx + 1));
                $headers[$name] = $value;
            }
            return strlen($header_line);
        });
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["username" => $username,"password" => $password]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        curl_exec($ch);
        curl_close($ch);

        if(!isset($headers['Set-Cookie'])) {
            $this->SendDebug('Cookie', 'Login failed', 0);
            return false;
        }
        $cookie = explode(';', $headers['Set-Cookie'])[0];

        $csrfToken = '';
        if (isset($headers['x-csrf-token'])) {
            $csrfToken = $headers['x-csrf-token'];
        }

        $this->SendDebug('Cookie', $cookie, 0);

        return [
            'cookie' => $cookie,
            'x-csrf-token' => $csrfToken
        ];
    }
}