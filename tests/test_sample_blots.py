"""
RLE Test Page Generator (sample_blots.py) Unit Tests
"""
# Written by Moses Chong
# First edition 2022/04/15
#
# PUBLIC DOMAIN, NO RIGHTS RESERVED
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software
# to the public domain worldwide. This software is distributed
# without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication
# along with this software. If not, see:
# <http://creativecommons.org/publicdomain/zero/1.0/>.

from unittest import TestCase
import sample_blots
try:
    from hashlib import blake2s
    hashcls = blake2s
except ImportError:
    from hashlib import md5
    hashcls = md5

# Test Data
DIGEST_BYTES = 8 # 64-bit for variable-length hashing algorithms
ARGS_MKFN_270K = {'w': 438, 'h': 620}
ARGS_FN_270K = {'i': 0, 'n': 271560}
ARGS_MKFN_MEGAPX = {'w': 876, 'h': 1240}

# Hash-based Test Suite
# ---------------------
# The output from the plotting functions can be very large when
# written out in full. Fortunately, the results are deterministic.
# This allows the use of hashes instead to verify results.
#
# BLAKE2s checksums are used hashers are available, with MD5 as a
# fallback option.
#
BLOT_FN_CASES_270K = {
    'all_set_270k': {
        'function': sample_blots._mk_fn_all_set, # maker function
        'args_mkfn': ARGS_MKFN_270K, # maker function arguments
        'args_fn': ARGS_FN_270K,     # plotter function arguments
        'b2sum': b'\x2e\x13\x44\x64\x9c\x39\xd7\xc5', # BLAKE2s sum
        'md5sum': b'\x33\x38\x39\x54\x57\xac\x91\x66\x05\xba\xab\xc4\x85\x99\x0b\xde'
    },
    'all_clear_270k': {
        'function': sample_blots._mk_fn_all_clear,
        'args_mkfn': ARGS_MKFN_270K,
        'args_fn': ARGS_FN_270K,
        'b2sum': b'\xa7\x7b\xd0\xf8\x53\x2a\x00\x51',
        'md5sum': b'\x0d\x77\x7e\x6e\xfb\x0d\x55\xc5\xbc\x41\x35\xbf\xb2\xd3\x00\x95'
    },
    'circle_270k': {
        'function': sample_blots._mk_fn_circle,
        'args_mkfn': ARGS_MKFN_270K,
        'args_fn': ARGS_FN_270K,
        'b2sum': b'\x42\xf5\x11\x47\x52\x73\xdf\x0b',
        'md5sum': b'\x67\x5c\x46\x37\xc9\x41\xdc\xd3\xd9\xcf\x55\x7b\x58\xaf\xde\x41'
    },
    'incr_runs_270k': {
        'function': sample_blots._mk_fn_incr_runs,
        'args_mkfn': ARGS_MKFN_270K,
        'args_fn': ARGS_FN_270K,
        'b2sum': b'\xdd\x68\x8b\x3d\x2a\xeb\x26\x4e',
        'md5sum': b'\xde\x71\x7f\x53\x63\xde\x1b\x08\xe4\xf8\x1c\x84\x2d\xf6\xcb\x5f'
    },
    'mirrored_incr_runs_270k': {
        'function': sample_blots._mk_fn_mirrored_incr_runs,
        'args_mkfn': ARGS_MKFN_270K,
        'args_fn': ARGS_FN_270K,
        'b2sum': b'\x14\x4b\xa0\x30\xc1\xfa\xbb\x43',
        'md5sum': b'\xff\xb8\x2e\x6e\xbb\x32\xfd\xc1\x07\x21\xa9\xb7\xb7\x30\xe8\x8b'
    },
    'quarter_diagonal_270K': {
        'function': sample_blots._mk_fn_quarter_diagonal,
        'args_mkfn': ARGS_MKFN_270K,
        'args_fn': ARGS_FN_270K,
        'b2sum': b'\xe9\x9b\x49\xa3\x29\xec\x1c\x84',
        'md5sum': b'\x1c\xa4\x69\x13\xe0\xd4\x72\x96\x5d\x28\x06\xb9\x23\x22\xdd\xfc'
    },
}

# Test Classes

class BlotFunctionTests(TestCase):

    def test_plot_270k(self):
        for k in BLOT_FN_CASES_270K.keys():
            with self.subTest(test=k):
                tcase = BLOT_FN_CASES_270K[k]
                args_mkfn = tcase['args_mkfn']
                args_fn = tcase['args_fn']
                mk_fn = tcase['function']
                fn = mk_fn(**args_mkfn)
                samp = bytes(x for x in fn(**args_fn))
                if hashcls is blake2s:
                    samp_hasher = hashcls(samp, digest_size=DIGEST_BYTES)
                    self.assertEqual(samp_hasher.digest(), tcase['b2sum'])
                else:
                    samp_hasher = hashcls(samp)
                    self.assertEqual(samp_hasher.digest(), tcase['md5sum'])

class P4Tests(TestCase):
    VALUE = 127

    def test_p4_get_row_div_8(self):
        """Get a P4 row for a bitmap with a divisible-by-8 width"""
        sample_8 = sample_blots._p4_get_row(8, [self.VALUE,]*8, self.VALUE)
        self.assertEqual([x for x in sample_8], [255,])
        sample_64 = sample_blots._p4_get_row(64, [self.VALUE,]*64, self.VALUE)
        self.assertEqual([x for x in sample_64], [255,]*8)

    def test_p4_get_row_non_div_8(self):
        """Get a P4 row for a bitmap with a non-divisible-by-8 width"""
        sample_7 = sample_blots._p4_get_row(7, [self.VALUE,]*7, self.VALUE)
        self.assertEqual([x for x in sample_7], [254,])
        sample_31 = sample_blots._p4_get_row(31, [self.VALUE,]*31, self.VALUE)
        self.assertEqual([x for x in sample_31], [255, 255, 255, 254])
