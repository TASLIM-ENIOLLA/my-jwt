<?php

    class Base64URL{
        public function base64_encode($data){
            return str_replace(
                ['+', '/', '='],
                ['-', '_', ''],
                base64_encode($data)
            );
        }
        public function base64_decode($data){
            return base64_decode(str_replace(
                ['-', '_', ''],
                ['+', '/', '='],
                $data
            ));
        }
    }

    class JWT extends Base64URL{
        protected $raw_header = '';
        protected $raw_payload = '';
        protected $raw_secret = '';
        public function __construct($header, $secret){
            $this -> raw_header = $header;
            $this -> raw_secret = $secret;
        }
        public function createJWT($payload){
            $this -> raw_payload = $payload;

            $base64UrlHeader = $this -> base64_encode(json_encode($this -> raw_header));
            $base64UrlPayload = $this -> base64_encode(json_encode($this -> raw_payload));
            $base64UrlSignature = $this -> base64_encode(hash_hmac(
                'sha256',
                $base64UrlHeader . "." . $base64UrlPayload,
                $this -> raw_secret,
                true
            ));

            return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
        }
        public function authenticateJWT($jwt){
            $jwt = explode('.', $jwt);
            
            if(count($jwt) === 3){
                $header = $this -> base64_decode($jwt[0]);
                $payload = $this -> base64_decode($jwt[1]);
                $signature_hash = $jwt[2];

                $base64UrlSignature = $this -> base64_encode(hash_hmac(
                    'sha256',
                    $jwt[0] . "." . $jwt[1],
                    $this -> raw_secret,
                    true
                ));

                if($base64UrlSignature === $signature_hash){
                    return (Object) [
                        'auth' => true,
                        'raw_header' => json_decode($header),
                        'raw_payload' => json_decode($payload),
                        'signature_hash' => $signature_hash
                    ];
                }
            }
        }
    }

    $jwt = new JWT(
        ['typ' => 'JWT', 'alg' => 'HS256'],
        '19042001'
    );

?>
