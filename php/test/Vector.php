<?php
require_once 'PHPUnit/Framework.php';
require_once '../fshp.php';

class Vector extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->vectors =array(
            array('passwd' => 'test',
            'opts' => array('variant' => 0, 'salt' => '', 'rounds' => 1),
            'ciphertext' => '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M='
            ),
            array('passwd' => 'test',
                'opts' => array('variant' => 1, 'salt' => '12345678', 'rounds' => 4096),
                'ciphertext' => '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA=='
            ),
            array('passwd' => 'test',
                  'opts' => array('variant' => 2, 'salt' => '!@#$%^&*', 'rounds' => 1024),
                  'ciphertext' => '{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc='
            ),
            array('passwd' => 'test',
                  'opts' => array('variant' => 3, 'salt'=> 'FSHP', 'rounds' => 512),
                  'ciphertext' => '{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA='
            )
        );
    }
    
    public function testCrypt()
    {
        foreach ($this->vectors as $v) {
            $ciphertext = Crypt_FSHP::crypt($v['passwd'],
                                            $v['opts']['salt'],
                                            0,  // saltlen
                                            $v['opts']['rounds'],
                                            $v['opts']['variant']);
            $this->assertEquals($ciphertext, $v['ciphertext']);
        }
    }
    
    public function testCheck()
    {
        foreach ($this->vectors as $v) {
            $this->assertTrue(
                Crypt_FSHP::check($v['passwd'], $v['ciphertext'])
            );
        }
    }
}


?>