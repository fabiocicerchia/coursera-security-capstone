<?php

namespace App;

class Encrypt
{
    protected $key;
 
    public function __construct()
    {
        $this->key = openssl_random_pseudo_bytes(28);
    }
 
    public function setKey($key)
    {
        $this->key = $key;
    }
 
    public function getKey()
    {
        return $this->key;
    }
 
    public function encrypt($text)
    {
        $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($text, $cipher, $this->key, $options = OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, $this->key, $as_binary = true);
        $ciphertext = base64_encode($iv.$hmac.$ciphertext_raw);
 
        return $ciphertext;
    }
 
    public function decrypt($text, $key)
    {
        $c = base64_decode($text);
        $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len = 32);
        $ciphertext_raw = substr($c, $ivlen+$sha2len);
        $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary = true);
        if (hash_equals($hmac, $calcmac)) {
            return $original_plaintext;
        }
    }
}