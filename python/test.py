import unittest

import fshp


class TestFSHPCryptAndValidate(unittest.TestCase):

    def setUp(self):
        self.test_vectors = [
            {
             'passwd': 'test',
             'opts': {'v': 0, 's': '', 'r': 1},
             'hash': '{FSHP0|0|1}qUqP5cyxm6YcTAhz05Hph5gvu9M='
            },

            {
             'passwd': 'test',
             'opts': {'v': 1, 's': '12345678', 'r': 4096},
             'hash': '{FSHP1|8|4096}MTIzNDU2NzjTdHcmoXwNc0ff9+ArUHoN0CvlbPZpxFi1C6RDM/MHSA=='
            },

            {
             'passwd': 'test',
             'opts': {'v': 2, 's': '!@#$%^&*', 'r': 1024},
             'hash': '{FSHP2|8|1024}IUAjJCVeJir9dx/jPTFM5E0FpbGp5JqZ4cO4pf257/DoZ9CNVkYmKwb+V3D4wpkcu87anZ//pPc='
            },

            {
             'passwd': 'test',
             'opts': {'v': 3, 's': 'FSHP', 'r': 512},
             'hash': '{FSHP3|4|512}RlNIUA4i9JgmY1gNlSGLsfd+sz3UwNqadVLRdbP1/sGanLcZoMBUGX4giFdbHiZGVuvs480BWye+yVKjpDlbyVTOoxA='
            }
        ]

    def test_crypt(self):
        for v in self.test_vectors:
            genhash = fshp.crypt(v['passwd'],
                                 salt=v['opts']['s'],
                                 rounds=v['opts']['r'],
                                 variant=v['opts']['v'])

            self.assertEqual(genhash, v['hash'])

    def test_check(self):
        for v in self.test_vectors:
            self.failUnless(fshp.check(v['passwd'], v['hash']))


if __name__ == '__main__':
    unittest.main()
