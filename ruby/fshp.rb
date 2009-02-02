# Author: Berk D. Demir <bdd@mindcast.org>
# 
# Authors of this computer software disclaim their respective copyright
# on the source code and related documentation, thus releasing their work
# to Public Domain.
#
# In case you are forced by your lawyer to get a copyright license,
# you may contact any of the authors to get this software (and its related
# documentation) with a BSD type license.

require 'base64'
require 'digest'

class FSHP
  @@fshp_meta_fmtstr = '{FSHP%d|%d|%d}'
  @@fshp_regex = /\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)/
  
  def FSHP.crypt(passwd, salt=nil, saltlen=8, rounds=4096, variant=1)
    # Type cast to integer.
    saltlen, rounds, variant = [saltlen, rounds, variant].map { |e| e.to_i }
    
    # Ensure we have sane values for salt length and rounds.
    saltlen = 0 if saltlen < 0
    rounds  = 1 if rounds  < 1
     
    # Do we have a 'salt' already?
    if salt.nil?
      # Fill 'salt' with 'saltlen' random bytes.
      salt = ''
      saltlen.times { salt << rand(255) }
    else
      saltlen = salt.length
    end
    
    case variant
    when 0
      hash = Digest::SHA1.new
    when 1
      hash = Digest::SHA2.new(bitlen=256)
    when 2
      hash = Digest::SHA2.new(bitlen=384)
    when 3
      hash = Digest::SHA2.new(bitlen=512)
    else
      throw Exception.new("Unsupported FSHP variant '#{variant}'.")
    end
    
    digest = hash.update(salt + passwd).digest
    (rounds - 1).times {
      digest = hash.reset.update(digest).digest
    }
    
    meta = format(@@fshp_meta_fmtstr, variant, saltlen, rounds)
    b64saltdigest = Base64.encode64(salt + digest).delete("\n")
    
    return meta + b64saltdigest
  end
  
  def FSHP.check(passwd, ciphertext)
    # Regular expression match. Yes, it's ugly.
    return false if (meta = ciphertext.match(@@fshp_regex)).nil?
    
    variant, saltlen, rounds, b64saltdigest = meta[1,5]
    
    # Decode base64 string, read first 'saltlen' bytes to get 'salt'.
    salt = Base64.decode64(b64saltdigest)[0, saltlen.to_i]
    
    return crypt(passwd, salt, saltlen, rounds, variant) == ciphertext
  end
end