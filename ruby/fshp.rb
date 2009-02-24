# = FSHP: Fairly Secure Hashed Password
#
# FSHP is a salted, iteratively hashed password hashing implementation.
#
# Design principle is similar with PBKDF1 specification in RFC 2898 
# (a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0)
#
# FSHP allows choosing the salt length, number of iterations and the
# underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
#
# == SECURITY:
# Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.
# - 8 byte salt renders rainbow table attacks impractical by multiplying the
#   required space with 2^64.
# - 4096 iterations causes brute force attacks to be fairly expensive.
# - There are no known attacks against SHA-256 to find collisions with
#   a computational effort of fewer than 2^128 operations at the time of
#   this release.
#
# == BASIC OPERATION:
# Calling <em>crypt()</em> with a single parameter of cleartext password, implies
# the default configuration of FSHP1.
# - _saltlen_: 8 bytes
# - _rounds_: 4096
# - _variant_: 1 (SHA-256)
#
#  >> fsh = FSHP.crypt('OrpheanBeholderScryDoubt')
#  => "{FSHP1|8|4096}GVSUFDAjdh0vBosn1GUhzGLHP7BmkbCZVH/3TQqGIjADXpc+6NCg3g=="
#  >> FSHP.check('OrpheanBeholderScryDoubt', fsh)
#  => true
#
# == CUSTOMIZING THE CRYPT:
# Let's set a higher password storage security baseline.
# - Increase the salt length from default 8 to 16.
# - Increase the hash rounds from default 4096 to 8192.
# - Select FSHP3 with SHA-512 as the underlying hash algorithm.
#  >> FSHP.crypt('ExecuteOrder66', nil, 16, 8192, 3)
#  => "{FSHP3|16|8192}0aY7rZQ+/PR+Rd5/I9ssRM7cjguyT8ibypNaSp/U1uziNO3BVlg5qPUng+zHUDQC3ao/JbzOnIBUtAeWHEy7a2vZeZ7jAwyJJa2EqOsq4Io="
#
#
# Author::    Berk D. Demir (mailto:bdd@mindcast.org)
# Copyright:: Author(s) of this computer software disclaim their respective
#             copyright on the source code and related documentation, thus
#             releasing their work to Public Domain.
# License::   Public Domain
#             In case you are forced by your lawyer to get a copyright license,
#             you may contact any of the authors to get this software
#             (and its related documentation) with a BSD type license.
#
# GitHub::    http://github.com/bdd/fshp
# RubyForge:: http://rubyforge.org/projects/fshp

require 'base64'
require 'digest'

class FSHP
  FSHP_META_FMTSTR = '{FSHP%d|%d|%d}'
  FSHP_REGEX = /\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)/
  
  # Create FSHP ciphertext for supplied cleartext password.
  #
  # - If salt is nil, saltlen bytes of random salt is generated.
  # - rounds: Number of hash iterations
  # - variant: FSHP Variant
  #   - 0: SHA-1    (not recommended)
  #   - 1: SHA-256  (default)
  #   - 2: SHA-384
  #   - 3: SHA-512
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
      raise ArgumentError, "Unsupported FSHP variant: #{variant}."
    end
    
    digest = hash.update(salt + passwd).digest
    (rounds - 1).times {
      digest = hash.reset.update(digest).digest
    }
    
    meta = format(FSHP_META_FMTSTR, variant, saltlen, rounds)
    b64saltdigest = Base64.encode64(salt + digest).delete("\n")
    
    return meta + b64saltdigest
  end
  
  # Check if supplied cleartext password matches supplied FSHP ciphertext.
  # - passwd: cleartext password
  # - ciphertext: FSHP hash to check against.
  def FSHP.check(passwd, ciphertext)
    # Regular expression match. Yes, it's ugly.
    return false if (meta = ciphertext.match(FSHP_REGEX)).nil?
    
    variant, saltlen, rounds, b64saltdigest = meta[1,5]
    
    # Decode base64 string, read first 'saltlen' bytes to get 'salt'.
    salt = Base64.decode64(b64saltdigest)[0, saltlen.to_i]
    
    return crypt(passwd, salt, saltlen, rounds, variant) == ciphertext
  end
end

