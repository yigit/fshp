<?php
# Author: Berk D. Demir <bdd@mindcast.org>
# 
# Authors of this computer software disclaim their respective copyright
# on the source code and related documentation, thus releasing their work
# to Public Domain.
#
# In case you are forced by your lawyer to get a copyright license,
# you may contact any of the authors to get this software (and its related
# documentation) with a BSD type license.

class FSHP
{
    const fshp_meta_fmtstr = "{FSHP%d|%d|%d}";
    const fshp_regex = "/^\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$/";
    
    function crypt($passwd, $salt=NULL, $saltlen=8, $rounds=4096, $variant=1)
    {
        # Type cast to integer.
        $saltlen = (int) $saltlen;
        $rounds  = (int) $rounds;
        $variant = (int) $variant;
        
        # Do we have a 'salt' already?
        if ($salt == NULL) {
            # Fill 'salt' with 'saltlen' random bytes.
            $salt = '';
            for ($i = 0; $i < $saltlen; $i++)
                $salt[$i] = chr(rand(0, 255));
        } else
            $saltlen = strlen($salt);
        
        switch ($variant) {
            case 0: $hash_algo = "sha1"  ; break;
            case 1: $hash_algo = "sha256"; break;
            case 2: $hash_algo = "sha384"; break;
            case 3: $hash_algo = "sha512"; break;
            default:
                throw new Exception("Unsupported FSHP variant '${variant}'.");
        }
        
        $rawdigest = hash($hash_algo, $salt . $passwd, TRUE);
        for ($i = 0; $i < $rounds - 1; $i++)
            $rawdigest = hash($hash_algo, $rawdigest, TRUE);
        
        $meta = sprintf(self::fshp_meta_fmtstr, $variant, $saltlen, $rounds);
        $b64saltdigest = base64_encode($salt . $rawdigest);
        return $meta . $b64saltdigest;
    }
    
    function check($passwd, $ciphertext)
    {
        // Regular expression match. Yes, it's ugly.
        if (preg_match(self::fshp_regex, $ciphertext, $meta) == FALSE ||
            count($meta) != 5)
            return FALSE;
        
        /* RegExp Match Array:
         *   meta[0] => Cipher Text
         *   meta[1] => Variant
         *   meta[2] => Salt Length
         *   meta[3] => Number of Iterations
         *   meta[4] => Base64 encoded Salt || Raw Digest (b64saltdigest)
         */
        
        // Decode base64 string, read first 'saltlen' bytes to get 'salt'.
        $salt = substr(base64_decode($meta[4]), 0, $meta[2]);
        
        return self::crypt($passwd, $salt, $meta[2], $meta[3], $meta[1])
               == $ciphertext;
    }
}
?>