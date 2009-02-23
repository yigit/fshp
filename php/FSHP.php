<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Fairly Secure Hashed Passwords. A PBKDF1 similar implementation.
 *
 * Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed
 * password hashing implementation.
 *
 * Design principle is similar with PBKDF1 specification in RFC 2898 
 * (a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0)
 *
 * FSHP allows choosing the salt length, number of iterations and the
 * underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
 *
 * SECURITY:
 * Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.
 *  - 8 byte salt renders rainbow table attacks impractical by multiplying the
 *    required space with 2^64.
 *  - 4096 iterations causes brute force attacks to be fairly expensive.
 *  - There are no known attacks against SHA-256 to find collisions with
 *    a computational effort of fewer than 2^128 operations at the time of
 *    this release.
 *
 * BASIC OPERATION:
 * <code>
 * $fsh = Crypt_FSHP::crypt('OrpheanBeholderScryDoubt');
 * </code>
 * <samp>
 * Return Value:
 * {FSHP1|8|4096}GVSUFDAjdh0vBosn1GUhzGLHP7BmkbCZVH/3TQqGIjADXpc+6NCg3g==
 * </samp>
 * <code>
 * Crypt_FSHP::check('OrpheanBeholderScryDoubt', $fsh);
 * </code>
 * <samp>
 * Return Value:
 * true
 * </samp>
 *
 * CUSTOMIZING THE CRYPT:
 * Let's set a higher password storage security baseline.
 *  - Increase the salt length from default 8 to 16.
 *  - Increase the hash rounds from default 4096 to 8192.
 *  - Select FSHP3 with SHA-512 as the underlying hash algorithm.
 *
 * <code>
 * Crypt_FSHP::crypt('ExecuteOrder66', null, 16, 8192, 3);
 * </code>
 * <samp>
 * Return Value:
 * {FSHP3|16|8192}0aY7rZQ+/PR+Rd5/I9ssRM7cjguyT8ibypNaSp/.....wyJJa2EqOsq4Io=
 * </samp>
 *
 * PHP version 5
 *
 * @category Encryption
 * @package  Crypt_FSHP
 * @author   Berk D. Demir <bdd@mindcast.org>
 * @license  http://creativecommons.org/licenses/publicdomain/ Public Domain
 *           Author(s) of this computer software disclaim their respective
 *           copyright on the source code and related documentation, thus
 *           releasing their work to Public Domain.
 *           In case you are forced by your lawyer to get a copyright license,
 *           you may contact any of the authors to get this software
 *           (and its related documentation) with a BSD type license.
 * @version  Release: @release_version@
 * @link     http://github.com/bdd/fshp Git Repository
 * @link     http://pear.php.net/package/Crypt_FSHP
 * @since    File available since Release 0.2.2
 */

/**
 * Required PEAR package(s)
 */
require_once 'PEAR/Exception.php';

/**
 * Crypt_FSHP
 *
 * @category Encryption
 * @package  Crypt_FSHP
 * @author   Berk D. Demir <bdd@mindcast.org>
 * @license  http://creativecommons.org/licenses/publicdomain/ Public Domain
 *           Author(s) of this computer software disclaim their respective
 *           copyright on the source code and related documentation, thus
 *           releasing their work to Public Domain.
 *           In case you are forced by your lawyer to get a copyright license,
 *           you may contact any of the authors to get this software
 *           (and its related documentation) with a BSD type license.
 * @link     http://github.com/bdd/fshp Git Repository
 * @link     http://pear.php.net/package/Crypt_FSHP
 * @since    Class available since Release 0.2.2
 */
class Crypt_FSHP
{
    const FSHP_META_FMTSTR = '{FSHP%d|%d|%d}';
    const FSHP_REGEX = '/^\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$/';
    
    /**
     * Create FSHP ciphertext for supplied cleartext password.
     *
     * @param string  $passwd  Cleartext password
     * @param string  $salt    Salt to be concatenated. null for random auto fill.
     * @param integer $saltlen If $saltlen is null, create a random salt 
     *                         this bytes long.
     * @param integer $rounds  Number of hash rounds.
     * @param integer $variant FSHP Variant.
     *                         0 => SHA1, 1 => SHA256, 2 => SHA384, 3 => SHA512
     *
     * @return string Hashed password packed with FSHP meta.
     * @throws Crypt_FSHP_UnsupportedVariantException
     *         If variant is unknown or underlying hash algorithm is not available.
     */
    public function crypt($passwd, $salt=null, $saltlen=8, $rounds=4096, $variant=1)
    {
        // Type cast to integer.
        $saltlen = (int) $saltlen;
        $rounds  = (int) $rounds;
        $variant = (int) $variant;
        
        // Ensure we have sane values for salt length and rounds.
        if ($saltlen < 0) {
            $saltlen = 0;
        }
        if ($rounds  < 1) {
            $rounds = 1;
        }
        
        // Do we have a 'salt' already?
        if ($salt == null) {
            // Fill 'salt' with 'saltlen' random bytes.
            $salt = '';
            for ($i = 0; $i < $saltlen; $i++) {
                $salt[$i] = chr(rand(0, 255));
            }
        } else {
            $saltlen = strlen($salt);
        }
        
        switch ($variant) {
        case 0: $hash_algorithm = 'sha1';
            break;
        case 1: $hash_algorithm = 'sha256';
            break;
        case 2: $hash_algorithm = 'sha384';
            break;
        case 3: $hash_algorithm = 'sha512';
            break;
        default:
            throw new Crypt_FSHP_UnsupportedVariantException($variant);
        }
        
        @$rawdigest = hash($hash_algorithm, $salt . $passwd, true);
        if ($rawdigest == false) {
            /*
             * Variant selected hash algorithm is not supported in this
             * PHP distritbution.
             */
            $message = "$variant. PHP hash() didn't recognize " .
                       "'$hash_algorithm' algorithm";
            throw new Crypt_FSHP_UnsupportedVariantException($msg);
        }
        
        for ($i = 1; $i < $rounds; $i++) {
            $rawdigest = hash($hash_algorithm, $rawdigest, true);
        }
        
        $meta = sprintf(self::FSHP_META_FMTSTR, $variant, $saltlen, $rounds);
        $b64saltdigest = base64_encode($salt . $rawdigest);
        return $meta . $b64saltdigest;
    }
    
    /**
     * Check if supplied cleartext password matches supplied FSHP ciphertext.
     *
     * @param string $passwd     Cleartext password
     * @param string $ciphertext Hashed password packed with FSHP meta
     *
     * @return boolean
     * @throws Crypt_FSHP_UnsupportedVariantException
     *         If variant is unknown or underlying hash algorithm is not available.
     */
    public function check($passwd, $ciphertext)
    {
        // Regular expression based tokenizer.
        if (preg_match(self::FSHP_REGEX, $ciphertext, $meta) == false ||
            count($meta) != 5) {
            return false;
        }
        
        /* Regexp Match Array:
         *   $meta[0] => Ciphertext
         *   $meta[1] => Variant
         *   $meta[2] => Salt Length
         *   $meta[3] => Number of Iterations
         *   $meta[4] => Base64 encoded Salt . Raw Digest (b64saltdigest)
         */
        
        // Decode base64 string, read first 'saltlen' bytes to get 'salt'.
        $salt = substr(base64_decode($meta[4]), 0, $meta[2]);
        
        return self::crypt($passwd, $salt, $meta[2], $meta[3], $meta[1]) ==
               $ciphertext;
    }
}

/**
 * Unsupported Variant Exception
 *
 * Thrown if supplied variant is unkown or underlying PHP distribution's
 * hash() function doesn't recognize variant specified hash algorithm.
 *
 * @category Encryption
 * @package  Crypt_FSHP
 * @author   Berk D. Demir <bdd@mindcast.org>
 * @license  http://creativecommons.org/licenses/publicdomain/ Public Domain
 *           Author(s) of this computer software disclaim their respective
 *           copyright on the source code and related documentation, thus
 *           releasing their work to Public Domain.
 *           In case you are forced by your lawyer to get a copyright license,
 *           you may contact any of the authors to get this software
 *           (and its related documentation) with a BSD type license.
 * @link     http://github.com/bdd/fshp Git Repository
 * @link     http://pear.php.net/package/Crypt_FSHP
 * @since    Class available since Release 0.2.2
 */
class Crypt_FSHP_UnsupportedVariantException extends PEAR_Exception
{
    /**
     * Constructor
     *
     * @param string $variant Variant
     * @param mixed  $p2      null
     * @param mixed  $p3      null
     */
    public function __construct($variant, $p2 = null, $p3 = null)
    {
        parent::__construct("Unsupported FSHP variant: $variant.", $p2, $p3);
    }
}
?>