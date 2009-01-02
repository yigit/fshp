require 'test/unit'
require 'fshp'

class TC_FSHP < Test::Unit::TestCase
  def setup
    @test_vectors = [
      { :passwd =>  'test',
        :opts =>  {:v =>  0, :s =>  '', :r =>  1},
        :hash =>  '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M=' },
      { :passwd =>  'test',
        :opts =>  {:v =>  1, :s =>  '12345678', :r =>  4096},
        :hash =>  '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA==' },
      { :passwd =>  'test',
        :opts =>  {:v =>  2, :s =>  '!@#$%^&*', :r =>  1024},
        :hash =>  '{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc=' },
      { :passwd =>  'test',
        :opts =>  {:v =>  3, :s =>  'FSHP', :r =>  512},
        :hash =>  '{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA=' },
    ]
  end
  
  def test_crypt
    @test_vectors.each do |v|
      genhash = FSHP.crypt(v[:passwd],
                           v[:opts][:s],
                           0,
                           v[:opts][:r],
                           v[:opts][:v])
      self.assert_equal genhash, v[:hash], \
                        "FSHP#crypt FAIL: variant #{v[:opts][:v]}"
    end
  end
  
  def test_validate
    @test_vectors.each do |v|
      self.assert FSHP.validate(v[:passwd], v[:hash]), \
                  "FSHP#validate FAIL: variant #{v[:opts][:v]}"
    end
  end
end

require 'test/unit/ui/console/testrunner'
Test::Unit::UI::Console::TestRunner.run(TC_FSHP)
