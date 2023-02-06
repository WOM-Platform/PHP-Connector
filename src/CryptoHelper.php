<?php
namespace WOM;

class CryptoHelper {

    public static function LoadPublicKeyFromString($keyData) {
        $key = new \phpseclib\Crypt\RSA;
        if(!$key->loadKey($keyData)){
            \WOM\Logger::$Instance->error("Public key is invalid");
            throw new \InvalidArgumentException("Public key is invalid");
        }

        \WOM\Logger::$Instance->debug("Public key loaded successfully from string");

        return $key;
    }

    public static function LoadPublicKeyFromPath($keyPath) {
        if(!file_exists($keyPath)){
            \WOM\Logger::$Instance->error("{$keyPath} public key file does not exist");
            throw new \InvalidArgumentException("{$keyPath} public key file does not exist");
        }

        $key = new \phpseclib\Crypt\RSA;
        if(!$key->loadKey(file_get_contents($keyPath))){
            \WOM\Logger::$Instance->error("{$keyPath} public key file is invalid");
            throw new \InvalidArgumentException("{$keyPath} public key file is invalid");
        }

        \WOM\Logger::$Instance->debug("Public key loaded successfully from path {$keyPath}");

        return $key;
    }

    public static function LoadPrivateKey($keyPath, $passphrase = null, $logger = null) {
        if(!file_exists($keyPath)){
            \WOM\Logger::$Instance->error("{$keyPath} private key file does not exist");
            throw new \InvalidArgumentException("{$keyPath} private key file does not exist");
        }

        $key = new \phpseclib\Crypt\RSA;
        if(!$key->loadKey(file_get_contents($keyPath))){
            \WOM\Logger::$Instance->error("{$keyPath} private key file is invalid");
            throw new \InvalidArgumentException("{$keyPath} private key file is invalid");
        }

        \WOM\Logger::$Instance->debug("Private key loaded successfully from path {$keyPath}");

        return $key;
    }

    public static function Encrypt($payload, $key){
        $key->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);

        \WOM\Logger::$Instance->debug("Encrypting payload of " . mb_strlen($payload) . " characters");
        \WOM\Logger::$Instance->debug($payload);

        $encrypted = $key->encrypt($payload);

        \WOM\Logger::$Instance->debug("Payload encrypted as " . mb_strlen($encrypted) . " characters");

        return $encrypted;
    }

    public static function Decrypt($payload, $key){
        $key->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);

        \WOM\Logger::$Instance->debug("Decrypting payload of " . mb_strlen($payload) . " characters");
        $decrypted = $key->decrypt(base64_decode($payload));

        \WOM\Logger::$Instance->debug("Payload decrypted as " . mb_strlen($decrypted) . " characters");
        \WOM\Logger::$Instance->debug($decrypted);

        return $decrypted;
    }

}
