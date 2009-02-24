===================================
FSHP: Fairly Secure Hashed Password
===================================

What is FSHP?
-------------
Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed
password hashing implementation.

Design principle is similar with PBKDF1 specification in RFC 2898 
*(a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0)*

FSHP allows choosing the salt length, number of iterations and the
underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).

Security
--------
Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.

- 8 byte salt renders rainbow table attacks impractical by multiplying the
  required space with 2^64.
- 4096 iterations causes brute force attacks to be fairly expensive.
- There are no known attacks against SHA-256 to find collisions with
  a computational effort of fewer than 2^128 operations at the time of
  this release.


Implementations
---------------
- Python: Tested with 2.3.5 *(w/ hashlib)*, 2.5.1, 2.6.1
    
    Available in PyPI. http://pypi.python.org/pypi/fshp
    
    *Install:* easy_install fshp
      
- Ruby  : Tested with 1.8.6
    
    Available in RubyForge. http://rubyforge.org/projects/fshp/
    
    *Install:* gem install fshp

- Perl  : Tested with 5.8.8
    
    Available in CPAN http://search.cpan.org/~bdd/Crypt-FSHP/
    
    *Install:* perl -MCPAN -e 'install Crypt::FSHP'
      
- PHP5  : Tested with 5.2.6
- Java  : Tested with 1.4, 1.5, 1.6.
  Dependency: Apache Commons - Codec (Base64)

Everyone is more than welcome to create missing language implementations or
polish the current ones.


Basic Operation
---------------
Calling *crypt()* with a single parameter of cleartext password, implies
the default configuration of FSHP1.
- *salt length*: 8 bytes long random salt will be generated.
- *hash rounds*: 4096 iterations of hashing will be applied in output chaining mode.
- *FSHP variant*: Variant 1 uses SHA-256 as underlying hash function.

>>> hashed_pw = fshp.crypt('OrpheanBeholderScryDoubt')
>>> print hashed_pw
{FSHP1|8|4096}GVSUFDAjdh0vBosn1GUhzGLHP7BmkbCZVH/3TQqGIjADXpc+6NCg3g==
>>> fshp.check('OrpheanBeholderScryDoubt', hashed_pw)
True


Customizing the Crypt
---------------------
Let's set a higher password storage security baseline.

- Increase the salt length from default 8 to 16.
- Increase the hash rounds from default 4096 to 8192.
- Select FSHP3 with SHA-512 as the underlying hash algorithm.
    
>>> hashed_pw = fshp.crypt('ExecuteOrder66', saltlen=16, rounds=8192, variant=3)
>>> print hashed_pw
{FSHP3|16|8192}0aY7rZQ+/PR+Rd5/I9ssRM7cjguyT8ibypNaSp/U1uziNO3BVlg5qPUng+zHUDQC3ao/JbzOnIBUtAeWHEy7a2vZeZ7jAwyJJa2EqOsq4Io=
