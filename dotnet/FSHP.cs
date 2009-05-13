/* FSHP .NET 2.0 Implementation
 *
 * Authors:
 * - Abraham Fournier <vaquito@gmail.com>
 *
 * Authors of this computer software disclaim their respective copyright
 * on the source code and related documentation, thus releasing their work
 * to Public Domain.

 * In case you are forced by your lawyer to get a copyright license,
 * you may contact any of the authors to get this software (and its related
 * documentation) with a BSD type license.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace fshp
{
    /// <summary>
    /// Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed password hashing
    /// implementation.
    /// </summary>
    /// <remarks>
    /// Design principle is similar with PBKDF1 specification in RFC 2898
    /// (a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0.)
    ///
    /// FSHP allows choosing the salt length, number of iterations and the
    /// underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
    ///
    /// SECURITY:
    /// Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.
    ///
    /// - 8 byte salt renders rainbow table attacks impractical by multiplying
    ///   required table space with 2^64.
    /// - 4096 iterations causes brute force attacks to be fairly expensive.
    /// - There are no known attacks against SHA-256 to find collisions with
    ///   a computational effort fewer than 2^128 operations at the time of
    ///   this release.
    /// </remarks>
    public class FSHP
    {
        /// <summary>
        /// Returns the FSHP hash of password with default parameters.
        /// </summary>
        /// <param name="password">the password to crypt</param>
        /// <returns>FSHP hash of password.</returns>
        public static String crypt(string password)
        {
            return FSHP.crypt(Encoding.UTF8.GetBytes(password), null, 8, 4096, 1);
        }

        /// <summary>
        ///  Returns the FSHP hash of password
        /// </summary>
        /// <param name="password">Contents will be encoded to bytes with UTF-8.</param>
        /// <param name="saltlen">Length of the salt to be generated.</param>
        /// <param name="rounds">Number of hashing rounds.</param>
        /// <param name="variant">FSHP variant indicating the behaviour and/or hashing algorithm
        ///  to be used.
        ///  0: SHA-1 (not recommended)
        ///  1: SHA-256
        ///  2: SHA-384
        ///  3: SHA-512
        /// </param>
        /// <returns>FSHP hash of password.</returns>
        public static String crypt(string password, int saltlen, int rounds, int variant)
        {
            return FSHP.crypt(Encoding.UTF8.GetBytes(password), null, saltlen, rounds, variant);
        }

        /// <summary>
        /// Validates the input clear text password matches the ciphertext.
        /// </summary>
        /// <param name="password">users password</param>
        /// <param name="ciphertext">Hashed Password to match aganist</param>
        /// <returns>true if ciphertext is a valid hash of password</returns>
        public static Boolean check(string password, string ciphertext)
        {
            return check(Encoding.UTF8.GetBytes(password), ciphertext);
        }

        /// <summary>
        ///  Returns the FSHP hash of password
        /// </summary>
        /// <param name="password">Encoded to bytes with UTF-8.</param>
        /// <param name="salt">Byte representation of salt to be used in hashing Encoded to bytes with UTF-8.</param>
        /// <param name="saltlen">Length of the salt to be generated.</param>
        /// <param name="rounds">Number of hashing rounds.</param>
        /// <param name="variant">FSHP variant indicating the behaviour and/or hashing algorithm
        ///  to be used.
        ///  0: SHA-1 (not recommended)
        ///  1: SHA-256
        ///  2: SHA-384
        ///  3: SHA-512
        /// </param>
        /// <returns>FSHP hash of password</returns>
        public static String crypt(byte[] password, byte[] salt, int saltlen, int rounds, int variant)
        {
            // Ensure we have sane values for salt length and rounds.
            if (saltlen < 0)
                saltlen = 0;
            if (rounds < 1)
                rounds = 1;

            // if salt is null, we generate a random one.
            RNGCryptoServiceProvider CryptoRng = new RNGCryptoServiceProvider();

            if (salt == null) {
                salt = new byte[saltlen];
                CryptoRng.GetBytes(salt);
            } else {
                saltlen = salt.Length;
            }

            HashAlgorithm hash;
            switch (variant) {
                case 0:
                    hash = new SHA1Managed();
                    break;
                case 1:
                    hash = new SHA256Managed();
                    break;
                case 2:
                    hash = new SHA384Managed();
                    break;
                case 3:
                    hash = new SHA512Managed();
                    break;
                default:
                    throw new Exception();
            }

            hash.Initialize();

            byte[] saltedPassword = new byte[salt.Length + password.Length];

            salt.CopyTo(saltedPassword, 0);
            password.CopyTo(saltedPassword, salt.Length);

            // Round 1
            byte[] hashBytes = hash.ComputeHash(saltedPassword);

            // ...and other rounds.
            for (int i = 1; i < rounds; i++) {
                hashBytes = hash.ComputeHash(hashBytes);
            }

            string meta = "{FSHP" + variant + "|" + saltlen + "|" + rounds +"}";
            byte[] saltdigest = new byte[salt.Length + hashBytes.Length];
            salt.CopyTo(saltdigest, 0);
            hashBytes.CopyTo(saltdigest, salt.Length);

            string b64saltdigest = Convert.ToBase64String(saltdigest);

            return meta + b64saltdigest;
        }


        private const String fshpRegex = @"(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$";
        /// <summary>
        /// Validates the input clear text password matches the ciphertext.
        /// <param name="password"> Byte representation of clear text password.</param>
        /// <param name="ciphertext"> Hashed Password to match aganist.</param>
        /// <returns>true if ciphertext is a valid hash of password</returns>
        /// </summary>
        private static Boolean check(byte[] password, string ciphertext)
        {
            Regex regex = new Regex(fshpRegex, RegexOptions.Compiled);

            string[] mc = regex.Split(ciphertext, 4, 5);
            int variant = Convert.ToInt32(mc[1]);
            int saltlen = Convert.ToInt32(mc[2]);
            int rounds = Convert.ToInt32(mc[3]);

            byte[] saltdigest = Convert.FromBase64String(Convert.ToString(mc[4]));

            byte[] salt = new byte[saltlen];
            Array.ConstrainedCopy(saltdigest, 0, salt, 0, saltlen);

            return crypt(password, salt, saltlen, rounds, variant).Equals(ciphertext);
        }
    }
}