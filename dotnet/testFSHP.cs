using System;
using System.Collections.Generic;
using System.Text;

namespace fshp
{
    /// <summary>
    /// a test for fshp, just run
    /// </summary>
    public static class testFSHP
    {
        struct testCommands
        {
            string password;

            public byte[] Password
            {
                get { return Encoding.UTF8.GetBytes(password); }
            }
            string salt;
            public byte[] Salt
            {
                get
                {
                    if (salt == null)
                    {
                        return null;
                    }
                    else
                    {
                        return Encoding.UTF8.GetBytes(salt);
                    }
                }
            }

            int saltlen;
            public int Saltlen
            {
                get { return saltlen; }
            }
            int rounds;
            public int Rounds
            {
                get { return rounds; }
            }
            int variant;
            public int Variant
            {
                get { return variant; }
            }
            string fshp;

            public string Fshp
            {
                get { return fshp; }
            }
            public testCommands(string password, string salt, int saltlen,
                 int rounds, int variant, string fshp)
            {
                this.password = password;
                this.salt = salt;
                this.saltlen = saltlen;
                this.rounds = rounds;
                this.variant = variant;
                this.fshp = fshp;
            }

        }
        /// <summary>
        /// runs the test
        /// </summary>
        /// 
        public static void runTest()
        {
            List<testCommands> input = new List<testCommands>();
            /* FSHP[variant] | [saltlen] | [rounds] */
            input.Add(new testCommands("test", null, 0, 1, 0,
                "{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M="));
            input.Add(new testCommands("test", "12345678", 8, 4096, 1,
                 "{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA=="));
            input.Add(new testCommands("test", "!@#$%^&*", 8, 1024, 2,
                 "{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc="));
            input.Add(new testCommands("test", "FSHP", 4, 512, 3,
                 "{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA="));
            
            
            int counterTest = 0;
            foreach (testCommands command in input)
            {
                string fshpFromCrypt = FSHP.crypt(command.Password, command.Salt, command.Saltlen, command.Rounds, command.Variant);
                if (!fshpFromCrypt.Equals(command.Fshp))
                {
                    Console.WriteLine("***ERROR**** test " + counterTest.ToString() + ":" 
                        + Environment.NewLine + command.Fshp + Environment.NewLine 
                        + "not equal to return: " + Environment.NewLine + fshpFromCrypt);
                }
                {
                    Console.WriteLine("pass test " + counterTest.ToString());
                }
                counterTest++;
            }
        }
    }
}
