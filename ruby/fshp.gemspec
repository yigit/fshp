Gem::Specification.new do |s|
  s.name = 'fshp'
  s.version = '1.0.0'
  s.homepage = 'http://github.com/bdd/fshp'
  s.rubyforge_project = 'fshp'
  
  s.authors = ['Berk D. Demir']
  s.email = 'bdd@mindcast.org'
  
  s.files = ['fshp.rb', 'test.rb']
  s.require_path = '.'
  s.test_files = 'test.rb'
  
  s.has_rdoc = true
  s.rdoc_options << '--inline-source' << '--line-numbers' <<
                 '--title' << 'RDoc: FSHP' <<
                 '--exclude' << 'test.rb'
  
  s.summary = 'Fairly Secure Hashed Password (PBKDF1 implementation from RFC 2898/PKCS#5)'
  s.description = <<-EOF
  = FSHP: Fairly Secure Hashed Password
  
  FSHP is a salted, iteratively hashed password hashing implementation.
  
  Design principle is similar with PBKDF1 specification in RFC 2898 
  (a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0)
  
  FSHP allows choosing the salt length, number of iterations and the
  underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
  
  == SECURITY:
  Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.
  - 8 byte salt renders rainbow table attacks impractical by multiplying the
    required space with 2^64.
  - 4096 iterations causes brute force attacks to be fairly expensive.
  - There are no known attacks against SHA-256 to find collisions with
    a computational effort of fewer than 2^128 operations at the time of
    this release.
  
  == BASIC OPERATION:
  Calling <em>crypt()</em> with a single parameter of cleartext password, implies
  the default configuration of FSHP1.
  - _saltlen_: 8 bytes
  - _rounds_: 4096
  - _variant_: 1 (SHA-256)
  
   >> fsh = FSHP.crypt('OrpheanBeholderScryDoubt')
   => "{FSHP1|8|4096}GVSUFDAjdh0vBosn1GUhzGLHP7BmkbCZVH/3TQqGIjADXpc+6NCg3g=="
   >> FSHP.check('OrpheanBeholderScryDoubt', fsh)
   => true
  
  == CUSTOMIZING THE CRYPT:
  Let's set a higher password storage security baseline.
  - Increase the salt length from default 8 to 16.
  - Increase the hash rounds from default 4096 to 8192.
  - Select FSHP3 with SHA-512 as the underlying hash algorithm.
   >> FSHP.crypt('ExecuteOrder66', nil, 16, 8192, 3)
   => "{FSHP3|16|8192}0aY7rZQ+/PR+Rd5/I9ssRM7cjguyT8ibypNaSp/U1uziNO3BVlg5qPUng+zHUDQC3ao/JbzOnIBUtAeWHEy7a2vZeZ7jAwyJJa2EqOsq4Io="
  
  EOF
end

