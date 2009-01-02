<?php
    require('fshp.php');
    
    assert_options(ASSERT_ACTIVE, true);
    assert_options(ASSERT_BAIL, false);
    assert_options(ASSERT_WARNING, false);
    assert_options(ASSERT_CALLBACK, assertion_failed);
    
    $assertion_errors = 0;
    $asserted_case = "START";
    
    function assertion_failed($file, $line, $message)
    {
        global $assertion_errors, $asserted_case;
        
        printf("Assertion case for '$asserted_case' failed.\n");
        $assertion_errors++;
    }
    
    $test_vectors = array(
        array('passwd' => 'test',
              'opts' => array('v' => 0, 's' => '', 'r' => 1),
              'hash' => '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M='
        ),
        array('passwd' => 'test',
              'opts' => array('v' => 1, 's' => '12345678', 'r' => 4096),
              'hash' => '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA=='
        ),
        array('passwd' => 'test',
              'opts' => array('v' => 2, 's' => '!@#$%^&*', 'r' => 1024),
              'hash' => '{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc='
        ),
        array('passwd' => 'test',
              'opts' => array('v' => 3, 's'=> 'FSHP', 'r' => 512),
              'hash' => '{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA='
        )
    );
    
    foreach ($test_vectors as $v) {
        $genhash = FSHP::crypt($v['passwd'],
                               $v['opts']['s'],
                               0,
                               $v['opts']['r'],
                               $v['opts']['v']);
        $asserted_case = "FSHP::crypt() - variant " . $v['opts']['v'];
        assert($genhash == $v['hash']);
    }
    
    foreach ($test_vectors as $v) {
        $asserted_case = "FSHP::validate() - variant " . $v['opts']['v'];
        assert(FSHP::validate($v['passwd'], $v['hash']));
    }
    
    if ($assertion_errors > 0) {
        printf("FAILED with %d assertions.\n", $assertion_errors);
        exit(1);
    } else {
        print "OK\n";
        exit(0);
    }
?>
