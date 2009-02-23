<?php
require_once 'PHPUnit/Framework.php';
require_once '../fshp.php';

class API extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException Crypt_FSHP_UnsupportedVariantException
     */
    public function testUnsupportedVariantException()
    {
        // Variant 255
        Crypt_FSHP::crypt('', '', 0, 0, 255);
    }
    
    public function testDefaultCrypt()
    {
        $ciphertext = Crypt_FSHP::crypt('fshp');
        $re = preg_match(Crypt_FSHP::FSHP_REGEX, $ciphertext, $meta);
        
        $this->assertTrue($re != false); // regexp match succesful.
        $this->assertTrue(count($meta) == 5); // we got all fields.

        /* Regexp Match Array:
         *   $meta[0] => Ciphertext
         *   $meta[1] => Variant
         *   $meta[2] => Salt Length
         *   $meta[3] => Number of Iterations
         *   $meta[4] => Base64 encoded Salt . Raw Digest (b64saltdigest)
         */
        $this->assertTrue($meta[1] == 1); // variant = 1
        $this->assertTrue($meta[2] == 8); // saltlen = 8
        $this->assertTrue($meta[3] == 4096); // rounds = 4096
    }
    
    public function testAutofixSaltlenAndRounds()
    {
        $passwd = '';
        $ciphertext = Crypt_FSHP::crypt($passwd, null, -1, -1, 1);
        $re = preg_match(Crypt_FSHP::FSHP_REGEX, $ciphertext, $meta);
        
        $this->assertTrue($re != false); // regexp match succesful.
        $this->assertTrue(count($meta) == 5); // we got all fields.

        /* Regexp Match Array:
         *   $meta[0] => Ciphertext
         *   $meta[1] => Variant
         *   $meta[2] => Salt Length
         *   $meta[3] => Number of Iterations
         *   $meta[4] => Base64 encoded Salt . Raw Digest (b64saltdigest)
         */
        $this->assertTrue($meta[2] == 0); // fixed -1 saltlen to 0
        $this->assertTrue($meta[3] == 1); // fixed -1 rounds  to 1
        
        // ciphertext is a hash of our cleartext passwd.
        $this->assertTrue(Crypt_FSHP::check('', $ciphertext));
    }

}
?>