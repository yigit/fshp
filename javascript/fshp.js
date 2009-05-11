Codec = {
    UTF8: {
        encode: function (u_string) {
            u_string = u_string.replace(/\r\n/g, "n");
            var b_string = "";

            for (var n = 0; n < u_string.length; n++) {
                var c = u_string.charCodeAt(n);

                if (c < 128) {
                    b_string += String.fromCharCode(c);
                } else if ((c > 127) && (c < 2048)) {
                    b_string += String.fromCharCode((c >> 6) | 192);
                    b_string += String.fromCharCode((c & 63) | 128);
                } else {
                    b_string += String.fromCharCode((c >> 12) | 224);
                    b_string += String.fromCharCode(((c >> 6) & 63) | 128);
                    b_string += String.fromCharCode((c & 63) | 128);
                }
            }

            return b_string;
        }, /* End of 'encode' */

        decode: function (b_string) {
            var u_string = "";
            var i = 0;
            var c = c1 = c2 = 0;

            while (i < b_string.length) {
                c = b_string.charCodeAt(i);

                if (c < 128) {
                    u_string += String.fromCharCode(c);
                    i++;
                } else if ((c > 191) && (c < 224)) {
                    c2 = b_string.charCodeAt(i + 1);
                    u_string += String.fromCharCode(((c & 31) << 6) |
                                                     (c2 & 63));
                    i += 2;
                } else {
                    c2 = b_string.charCodeAt(i + 1);
                    c3 = b_string.charCodeAt(i + 2);
                    u_string += String.fromCharCode( ((c & 15) << 12) |
                                                     ((c2 & 63) << 6) |
                                                     (c3 & 63));
                    i += 3;
                }
            }
            return u_string;
        } /* End of 'decode' */
    }, /* End of UTF-8 */

    Base64: {
        A: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        encode: function (input) {
            var output = "";
            var chr1, chr2, chr3;
            var enc1, enc2, enc3, enc4;
            var i = 0;

            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);

                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;

                if (isNaN(chr2)) {
                    enc3 = enc4 = 64;
                } else if (isNaN(chr3)) {
                    enc4 = 64;
                }

                output = output +
                         this.A.charAt(enc1) + this.A.charAt(enc2) +
                         this.A.charAt(enc3) + this.A.charAt(enc4);
            }
            return output;
        }, /* End of 'encode' */

        decode: function (input) {
            var output = "";
            var chr1, chr2, chr3;
            var enc1, enc2, enc3, enc4;
            var i = 0;

            input = input.replace(/[^A-Za-z0-9+\/=]/g, "");

            while (i < input.length) {
                enc1 = this.A.indexOf(input.charAt(i++));
                enc2 = this.A.indexOf(input.charAt(i++));
                enc3 = this.A.indexOf(input.charAt(i++));
                enc4 = this.A.indexOf(input.charAt(i++));

                chr1 = (enc1 << 2) | (enc2 >> 4);
                chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                chr3 = ((enc3 & 3) << 6) | enc4;

                output = output + String.fromCharCode(chr1);

                if (enc3 != 64) {
                    output = output + String.fromCharCode(chr2);
                }
                if (enc4 != 64) {
                    output = output + String.fromCharCode(chr3);
                }
            }
            return output;
        } /* End of 'decode' */
    }, /* End of Base64 */

    str2binb: function (str) {
        var bin = Array();
        var mask = (1 << 8) - 1;
        for(var i = 0; i < str.length * 8; i += 8) {
            bin[i>>5] |= (str.charCodeAt(i / 8) & mask) << (24 - i % 32);
        }
        return bin;
    }, /* End of str2binb */

    binb2hex: function (i32arr) {
        var hex_tab = "0123456789abcdef";
        var str = "";
        for(var i = 0; i < i32arr.length * 4; i++) {
            str += hex_tab.charAt((i32arr[i>>2] >> ((3 - i%4)*8+4)) & 0x0F) +
                   hex_tab.charAt((i32arr[i>>2] >> ((3 - i%4)*8  )) & 0x0F);
        }
        return str;
    }, /* End of binb2hex */

    binb2str: function (i32arr) {
      str = "";
      for (var i = 0; i < i32arr.length * 4; i++) {
          str += String.fromCharCode((i32arr[i>>2] >> (3 - (i % 4)) * 8)
                                     & 0xFF);
      }
      return str;
    } /* End of binb2str */
} /* End of Codec */


function SHA1(msg) {

    function RotL(n, s) {
        var t4 = (n << s) | (n >>> (32 - s));
        return t4;
    };

    var blockstart;
    var i, j;
    var W = new Array(80);
    var H = new Array(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                      0xC3D2E1F0);
    var A, B, C, D, E;
    var tmp;

    var msg_len = msg.length;

    var words = new Array();

    for (i = 0; i < msg_len - 3; i += 4) {
        j = msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 |
            msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3);

        words.push(j);
    }

    switch (msg_len % 4) {
    case 0:
        i = 0x080000000;
        break;
    case 1:
        i = msg.charCodeAt(msg_len - 1) << 24 | 0x0800000;
        break;

    case 2:
        i = msg.charCodeAt(msg_len - 2) << 24 |
            msg.charCodeAt(msg_len - 1) << 16 |
            0x08000;
        break;

    case 3:
        i = msg.charCodeAt(msg_len - 3) << 24 |
            msg.charCodeAt(msg_len - 2) << 16 |
            msg.charCodeAt(msg_len - 1) << 8 |
            0x80;
        break;
    }

    words.push(i);

    while ((words.length % 16) != 14)
        words.push(0);

    words.push(msg_len >>> 29);
    words.push((msg_len << 3) & 0x0ffffffff);

    for (blockstart = 0; blockstart < words.length; blockstart += 16) {
        for (i = 0; i < 16; i++)
            W[i] = words[blockstart + i];

        for (i = 16; i <= 79; i++)
            W[i] = RotL(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

        A = H[0];
        B = H[1];
        C = H[2];
        D = H[3];
        E = H[4];

        for (i = 0; i <= 19; i++) {
            tmp = (RotL(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999)
                  & 0x0ffffffff;
            E = D; D = C; C = RotL(B, 30);
            B = A; A = tmp;
        }

        for (i = 20; i <= 39; i++) {
            tmp = (RotL(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) &
                  0x0ffffffff;
            E = D; D = C; C = RotL(B, 30);
            B = A; A = tmp;
        }

        for (i = 40; i <= 59; i++) {
            tmp = (RotL(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] +
                   0x8F1BBCDC) & 0x0ffffffff;
            E = D; D = C; C = RotL(B, 30);
            B = A; A = tmp;
        }

        for (i = 60; i <= 79; i++) {
            tmp = (RotL(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) &
                  0x0ffffffff;
            E = D; D = C; C = RotL(B, 30);
            B = A; A = tmp;
        }

        H[0] = (H[0] + A) & 0x0ffffffff;
        H[1] = (H[1] + B) & 0x0ffffffff;
        H[2] = (H[2] + C) & 0x0ffffffff;
        H[3] = (H[3] + D) & 0x0ffffffff;
        H[4] = (H[4] + E) & 0x0ffffffff;

    }

    return Codec.binb2str(H);
} /* End of SHA1 */


function SHA256(s) {

    function safe_add (x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    function S (X, n)     { return ( X >>> n ) | (X << (32 - n)); }
    function R (X, n)     { return ( X >>> n ); }
    function Ch(x, y, z)  { return ((x & y) ^ ((~x) & z)); }
    function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
    function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
    function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
    function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
    function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

    function core_sha256 (m, l) {
        var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
                          0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                          0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
                          0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                          0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
                          0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                          0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
                          0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                          0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
                          0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                          0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
                          0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                          0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
                          0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                          0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
                          0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);

        var H = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);

        var W = new Array(64);
        var a, b, c, d, e, f, g, h, i, j;
        var T1, T2;

        m[l >> 5] |= 0x80 << (24 - l % 32);
        m[((l + 64 >> 9) << 4) + 15] = l;

        for (var i = 0; i < m.length; i+=16 ) {
            a = H[0]; b = H[1]; c = H[2]; d = H[3];
            e = H[4]; f = H[5]; g = H[6]; h = H[7];

            for (var j = 0; j < 64; j++) {
                if (j < 16) W[j] = m[j + i];
                else W[j] = safe_add(
                              safe_add(
                                safe_add(Gamma1256(W[j - 2]), W[j - 7]),
                                Gamma0256(W[j - 15])
                              ),
                              W[j - 16]
                            );

                T1 = safe_add(
                       safe_add(
                         safe_add(
                           safe_add(h, Sigma1256(e)),
                           Ch(e, f, g)
                         ),
                         K[j]
                       ),
                       W[j]
                     );
                T2 = safe_add(Sigma0256(a), Maj(a, b, c));

                h = g; g = f; f = e; e = safe_add(d, T1);
                d = c; c = b; b = a; a = safe_add(T1, T2);
            }

            H[0] = safe_add(a, H[0]);
            H[1] = safe_add(b, H[1]);
            H[2] = safe_add(c, H[2]);
            H[3] = safe_add(d, H[3]);
            H[4] = safe_add(e, H[4]);
            H[5] = safe_add(f, H[5]);
            H[6] = safe_add(g, H[6]);
            H[7] = safe_add(h, H[7]);
        }

        return H;
    } /* End of 'core_sha256' */

    return Codec.binb2str(core_sha256(Codec.str2binb(s), s.length * 8));
} /* End of SHA256 */

FSHP = {
    FSHP_REGEX: /^\{FSHP(\d+)\|(\d+)\|(\d+)\}([\d\w\+\/=]+)$/,
               

    /* crypt:
     * passwd : UTF-8 String
     * options: { salt: ASCII String, saltlen: Int,
     *            rounds: Int, variant: Int (0, 1) }
     *
     * Options are optional. Single argument (passwd only) invocation
     * employs default options.
     */
    crypt: function(passwd, options) {
          var default_options = { saltlen: 8, rounds: 128, variant: 1 };
          var salt, saltlen, rounds, variant;

          if (arguments.length == 1)
              options = default_options;

          if (typeof options.saltlen == 'undefined')
              saltlen = default_options.saltlen;
          else {
              if (options.saltlen < 0)
                  saltlen = 0;
              else
                  saltlen = options.saltlen;
          }

          if (typeof options.rounds == 'undefined')
              rounds = default_options.rounds;
          else {
              if (options.rounds < 1)
                  rounds = 1;
              else
                  rounds = options.rounds;
          }

          if (typeof options.variant == 'undefined')
              variant = default_options.variant;
          else
              variant = options.variant;

          // Generate salt or already have one?
          if (typeof options.salt == 'undefined') {
              salt = "";
              for (var i = 0; i < saltlen; i++)
                  salt += String.fromCharCode(Math.ceil(Math.random() * 256))
          } else {
              salt = options.salt;
              saltlen = salt.length;
          }

          // XXX: SHA1 and SHA-256 support only for variants 0 and 1.
          switch (Number(variant)) {
          case 0:
            cryptoHashFunc = SHA1;
            break;
          case 1:
            cryptoHashFunc = SHA256;
            break
          default:
            throw "Unknown of unsupported variant: " + variant;
          }

          // Round 1
          digest = cryptoHashFunc(salt + Codec.UTF8.encode(passwd));

          // ...and other rounds
          for (var i = 1; i < rounds; i++)
              digest = cryptoHashFunc(digest);

          var meta = "{FSHP" + variant + "|" + saltlen + "|" + rounds + "}";
          var b64saltdigest = Codec.Base64.encode(salt + digest);

          return meta + b64saltdigest;
      }, /* End of 'crypt' */

      check: function(passwd, ciphertext) {
          var variant, saltlen, rounds, b64saltdigest;
          var match, salt;
          var crypt_opts;

          if ((match = ciphertext.match(FSHP.FSHP_REGEX)) === null)
              throw "Ciphertext is not a valid FSHP ciphertext: " + ciphertext;

          variant       = match[1];
          saltlen       = match[2];
          rounds        = match[3];
          b64saltdigest = match[4];

          salt = Codec.Base64.decode(b64saltdigest).substr(0, saltlen);
          crypt_opts = {salt: salt, rounds: rounds, variant: variant};

          return FSHP.crypt(passwd, crypt_opts) == ciphertext;
      } /* End of 'check' */
} /* End of FSHP */