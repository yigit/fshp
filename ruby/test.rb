require 'test/unit'
require 'fshp'

class TC_FSHP < Test::Unit::TestCase
  def setup
    @test_vectors = [
      { :passwd =>  'test',
        :opts =>  {:variant =>  0, :salt =>  '', :rounds =>  1},
        :ciphertext =>  '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=' },
      { :passwd =>  'test',
        :opts =>  {:variant =>  1, :salt =>  '12345678', :rounds =>  4096},
        :ciphertext =>  '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA==' },
      { :passwd =>  'test',
        :opts =>  {:variant =>  2, :salt =>  '!@#$%^&*', :rounds =>  1024},
        :ciphertext =>  '{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc=' },
      { :passwd =>  'test',
        :opts =>  {:variant =>  3, :salt =>  'FSHP', :rounds =>  512},
        :ciphertext =>  '{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA=' },
    ]
  end
  
  def test_crypt
    @test_vectors.each do |v|
      ciphertext = FSHP.crypt(v[:passwd],
                              v[:opts][:salt],
                              0, # saltlen
                              v[:opts][:rounds],
                              v[:opts][:variant])
                              
      self.assert_equal(ciphertext, v[:ciphertext])
    end
  end
  
  def test_check
    @test_vectors.each do |v|
      self.assert(FSHP.check(v[:passwd], v[:ciphertext]))
    end
  end
  
  def test_unsupported_variant_exception
    # Variant 255
    assert_raise ArgumentError do
      FSHP.crypt('', '', 0, 0, 255)
    end
  end
  
  def test_default_crypt
    ciphertext = FSHP.crypt('fshp')
    meta = ciphertext.match(FSHP::FSHP_REGEX)
    self.assert(meta)
    self.assert_equal(meta.length, 5)
    
    self.assert_equal(meta[1], '1')    # variant = 1
    self.assert_equal(meta[2], '8')    # saltlen = 8
    self.assert_equal(meta[3], '4096') # rounds = 4096
  end
  
  def test_autofix_saltlen_and_rounds
    passwd = 'fshp'
    ciphertext = FSHP.crypt(passwd, nil, -1, -1, 1)
    meta = ciphertext.match(FSHP::FSHP_REGEX)
    self.assert(meta)
    self.assert_equal(meta.length, 5)
    
    self.assert_equal(meta[2], '0') # fixed -1 saltlen to 0
    self.assert_equal(meta[3], '1') # fixed -1 rounds  to 1
    
    self.assert(FSHP.check(passwd, ciphertext))
  end
end

require 'test/unit/ui/console/testrunner'
Test::Unit::UI::Console::TestRunner.run(TC_FSHP)
