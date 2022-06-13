<?php


namespace Weishuiliang\RsaPhp;


class Rsa
{

    /**
     * 获取私钥
     * @return bool|resource
     */
    private static function getPrivateKey()
    {
        //私钥路径
        $abs_path = BASE_PATH . '/pem/qin' . '/rsa_private_key.pem';
        $content = file_get_contents($abs_path);
        return openssl_pkey_get_private($content);
    }

    /**
     * 获取公钥
     * @return bool|resource
     */
    private static function getPublicKey()
    {
        //公钥路径
        $abs_path = BASE_PATH . '/pem/qin' . '/rsa_public_key.pem';
        $content = file_get_contents($abs_path);
        return openssl_pkey_get_public($content);
    }

    /**
     * 私钥加密
     * @param string $data
     * @return null|string
     */
    public static function privEncrypt(string $data = '')
    {
        if (!is_string($data)) {
            return null;
        }
        return openssl_private_encrypt($data, $encrypted, self::getPrivateKey()) ? base64_encode($encrypted) : null;
    }

    /**
     * 公钥加密
     * @param string $data
     * @return null|string
     */
    public static function publicEncrypt($data = '')
    {
        if (!is_string($data)) {
            return null;
        }
        return openssl_public_encrypt($data, $encrypted, self::getPublicKey()) ? base64_encode($encrypted) : null;
    }

    /**
     * 私钥解密
     * @param string $encrypted
     * @return null
     */
    public static function privDecrypt($encrypted = '')
    {
        if (!is_string($encrypted)) {
            return null;
        }
        return (openssl_private_decrypt(base64_decode($encrypted), $decrypted, self::getPrivateKey())) ? $decrypted : null;
    }

    /**
     * 公钥解密
     * @param string $encrypted
     * @return null
     */
    public static function publicDecrypt($encrypted = '')
    {
        if (!is_string($encrypted)) {
            return null;
        }
        return (openssl_public_decrypt(base64_decode($encrypted), $decrypted, self::getPublicKey())) ? $decrypted : null;
    }

    /**
     * 公钥验签
     *
     * @author wsl
     * @param string $data
     * @param string $sign
     * @param int $algorithm
     * @return bool|null
     */
    public static function verify(string $data, string $sign, int $algorithm = OPENSSL_ALGO_MD5)
    {
        if (!is_string($data)) {
            return null;
        }
        return (bool)openssl_verify($data, base64_decode($sign), self::getPublicKey(), $algorithm);
    }

    /**
     * 私钥加签
     *
     * @author wsl
     * @param string $signString
     * @param int $algorithm
     * @return string
     */
    public static function sign(string $signString, int $algorithm = OPENSSL_ALGO_MD5) : string
    {
        //调用openssl内置签名方法，生成签名$sign
        openssl_sign($signString, $sign, self::getPrivateKey(), $algorithm);
        //释放资源
        return base64_encode($sign);
    }


}