/*
 * @(#) FSHP.java	0.2.0 2009/01/28
 * 
 * Authors:
 *   - Huseyin Cigeroglu <huseyincigeroglu@gmail.com>
 *   - Berk D. Demir <bdd@mindcast.org>
 *
 * Authors of this computer software disclaim their respective copyright
 * on the source code and related documentation, thus releasing their work
 * to Public Domain.
 *
 * In case you are forced by your lawyer to get a copyright license,
 * you may contact any of the authors to get this software (and its related
 * documentation) with a BSD type license.
 */

package fshp;

import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

/**
 * FSHP: Fairly Secure Hashed Password
 * 
 * Fairly Secure Hashed Password (FSHP) is a salted, iteratively hashed
 * password hashing implementation.
 * 
 * Design principle is similar with PBKDF1 specification in RFC 2898 
 * (a.k.a: PKCS #5: Password-Based Cryptography Specification Version 2.0.)
 * FSHP allows choosing the salt length, number of iterations and the
 * underlying cryptographic hash function among SHA-1 and SHA-2 (256, 384, 512).
 * 
 * SECURITY:
 * Default FSHP1 uses 8 byte salts, with 4096 iterations of SHA-256 hashing.
 *   - 8 byte salt renders rainbow table attacks impractical by multiplying
 *     required table space with 2^64.
 *   - 4096 iterations causes brute force attacks to be fairly expensive.
 *   - There are no known attacks against SHA-256 to find collisions with
 *     a computational effort fewer than 2^128 operations at the time of
 *     this release.
 *
 * @version 0.2.0
 * @author Huseyin Cigeroglu
 * @author Berk D. Demir
 */
public class FSHP  {
	public static String FSHP_REGEX =
		"^\\{FSHP(\\d+)\\|(\\d+)\\|(\\d+)\\}([\\d\\w\\+\\/=]+)$";
	
	
	/**
	 * Returns the FSHP hash of {@link passwd} with default parameters.
	 * - Salt Length =  8
	 * - Number of Rounds = 4096
	 * - Variant = 1 (SHA-256)
	 * 
	 * @param passwd String Password.
	 *               Contents will be encoded to bytes with UTF-8.
	 * @return       FSHP hash of {@link passwd}
	 */
	public static String crypt(String passwd)
		throws Exception
	{
		return FSHP.crypt(passwd.getBytes("UTF-8"),
					null, 8, 4096, 1);
	}
	
	
	/**
	 * Returns the FSHP hash of {@link passwd}
	 * 
	 * @param passwd String Password.
	 *               Contents will be encoded to bytes with UTF-8.
	 * @param saltlen Length of the salt to be generated.
	 *        provided. If salt is null, saltlen bytes of salt will be
	 *        auto generated.
	 * @param rounds Number of hashing rounds.
	 * @param variant FSHP variant indicating the behaviour and/or
	 *        hashing algorithm to be used.
	 *        0: SHA-1 (not recommended)
	 *        1: SHA-256
	 *        2: SHA-384
	 *        3: SHA-512
	 * @return       FSHP hash of {@link passwd}
	 */	
	public static String crypt(String passwd, int saltlen, int rounds, int variant)
		throws Exception
	{
		return FSHP.crypt(passwd.getBytes("UTF-8"),
					null, saltlen, rounds, variant);
	}
	
	
	/**
	 * Returns the hash of {@link passwd} 
	 *
	 * @param passwd Byte representation of clear text password.
	 * @param salt Byte representation of salt to be used in hashing.
	 * @param saltlen Length of the salt. Should be 0 if a salt is already
	 *        provided. If salt is null, saltlen bytes of salt will be
	 *        auto generated.
	 * @param rounds Number of hashing rounds.
	 * @param variant FSHP variant indicating the behaviour and/or
	 *        hashing algorithm to be used.
	 *        0: SHA-1 (not recommended)
	 *        1: SHA-256
	 *        2: SHA-384
	 *        3: SHA-512
	 * @return       FSHP hash of {@link passwd}
	 */	
	public static String crypt(byte[] passwd, byte[] salt, int saltlen, int rounds, int variant)
		throws Exception
	{
		if (salt == null) {
			salt = new byte[saltlen];
			new SecureRandom().nextBytes(salt);
		} else
			saltlen = salt.length;
	
		HashMap<Integer,String> algoMap = new HashMap<Integer,String>();
		algoMap.put(0, "SHA-1");
		algoMap.put(1, "SHA-256");
		algoMap.put(2, "SHA-384");
		algoMap.put(3, "SHA-512");
		
		MessageDigest md;
		try {
			if (!algoMap.containsKey(variant))
				throw new NoSuchAlgorithmException();
				
			md = MessageDigest.getInstance(algoMap.get(variant));
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("Unsupported FSHP variant " + variant);
		}
	
		md.update(salt);
		md.update(passwd);
		byte[] digest = md.digest();
		
		for(int i = 1; i < rounds; i++) {
			md.reset();
			md.update(digest);
			digest = md.digest();
		}
		
		String meta = "{FSHP" + 
				variant + "|" + saltlen + "|" + rounds +
			 	"}";

		byte[] saltdigest = new byte[salt.length  + digest.length];
		System.arraycopy(salt, 0, saltdigest, 0, salt.length);
		System.arraycopy(digest, 0, saltdigest, salt.length, digest.length);

		byte[] b64saltdigest = Base64.encodeBase64(saltdigest);
		
		return meta + new String(b64saltdigest, "US-ASCII");
	}
	
	
	/**
	 * Validates the input clear text password matches the ciphertext.
	 *
	 * @param passwd String Password.
	 *               Contents will be encoded to bytes with UTF-8.
	 * @param ciphertext Hashed Password to match aganist.
	 * @return Boolean
	 */
	public static boolean check(String passwd, String ciphertext)
		throws Exception
	{
		return FSHP.check(passwd.getBytes("UTF-8"), ciphertext);
	}
	
	
	/**
	 * Validates the input clear text password matches the ciphertext.
	 *
	 * @param passwd Byte representation of clear text password.
	 * @param ciphertext Hashed Password to match aganist.
	 * @return Boolean
	 */	
	public static boolean check(byte[] passwd, String ciphertext)
		throws Exception
	{
		/* Regular expression match. Yes, it's ugly. */
		Pattern regex = Pattern.compile(FSHP_REGEX);
		Matcher match = regex.matcher(ciphertext);
		if (!match.matches())
			return false;

		int variant = Integer.parseInt(match.group(1));
		int saltlen = Integer.parseInt(match.group(2));
		int rounds  = Integer.parseInt(match.group(3));
		byte[] b64saltdigest = match.group(4).getBytes("US-ASCII");
		
		/* Decode base64 string, read first 'saltlen' bytes to get 'salt'. */
		byte[] saltdigest = Base64.decodeBase64(b64saltdigest);
		byte[] salt = new byte[saltlen];
		System.arraycopy(saltdigest, 0, salt, 0, saltlen);
		
		return crypt(passwd, salt, saltlen, rounds, variant).equals(ciphertext);
	}
}