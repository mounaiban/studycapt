"""
SCoA Toolkit (scoa.py) Unit Tests
"""
# Written by Moses Chong
# First edition 2022/05/16
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
import scoa

LINE_SIZE = 8
LINE_SIZE_LONG = 1000

class ScoaDecoderTests(TestCase):
    # NOTE: The test data are interlaced with the test methods,
    # not in a separate section

    WRITEOUT_CASES = {
        'old_only': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'np': 8},
            'expected': b'\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0',
        },
        'repeat_only': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'np': 0, 'nr': 8, 'rb': 0xD0},
            'expected': b'\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0',
        },
        'repeat_then_new': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'nr': 4, 'rb': 0xDE, 'ub': b'\x9a\x9b\x9c\x9d'},
            'expected': b'\xde\xde\xde\xde\x9a\x9b\x9c\x9d',
        },
        'new_only': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'ub': b'\x9a\x9b\x9c\x9d\x9e\x9f\xaa\xab'},
            'expected': b'\x9a\x9b\x9c\x9d\x9e\x9f\xaa\xab',
        },
        'old_then_repeat': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'np': 4, 'nr': 4, 'rb': 0xD0},
            'expected': b'\xf0\xf0\xf0\xf0\xd0\xd0\xd0\xd0',
        },
        'old_then_new': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'test_args': {'np': 4, 'ub': b'\x9a\x9b\x9c\x9d'},
            'expected': b'\xf0\xf0\xf0\xf0\x9a\x9b\x9c\x9d',
        },
    }

    def test_writeout(self):
        for t in self.WRITEOUT_CASES.values():
            with self.subTest(test=t):
                sd = scoa.SCoADecoder(**t['init_args'])
                samp = bytes(sd._writeout(**t['test_args']))
                self.assertEqual(samp, t['expected'])

    # NOTE: For now, 'old' means copied from previous line,
    # 'new' means new, uncompressed bytes from input and
    # 'repeat' means repeated, new compressed bytes from input.
    DECODE_CASES = {
        'new': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'input': b'\x38\x00\x01\x02\x03\x04\x05\x06',
            'expected': b'\x00\x01\x02\x03\x04\x05\x06',
        },
        'new_long': {
            'init_args': {'line_size': LINE_SIZE_LONG, 'init_value': b'\xf0'},
            'input': b''.join((
                b'\xbf\xf8', b'\x0a'*255,
                b'\xbf\xf8', b'\x0b'*255,
                b'\xbf\xf8', b'\x0c'*255,
                b'\xbd\xd8', b'\x0d'*235,
            )),
            'expected': b''.join((
                b'\x0a'*255, b'\x0b'*255, b'\x0c'*255, b'\x0d'*235
            ))
        },
        'repeat': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'input': b'\x78\x9a',
            'expected': b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
        },
        'repeat_long': {
            'init_args': {'line_size': LINE_SIZE_LONG, 'init_value': b'\xf0'},
            'input': b'\xbf\xb8\x9a\xbf\xb8\x9a\xbf\xb8\x9a\xbd\x98\x9a',
            'expected': b'\x9a'*1000
        },
        'repeat_then_new': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'input': b'\xe4\x90\x01\x02\x03\x04',
            'expected': b'\x90\x90\x90\x90\x01\x02\x03\x04',
        },
        'repeat_long_then_new': {
            'init_args': {'line_size': LINE_SIZE_LONG, 'init_value': b'\xf0'},
            'input': b'\xbf\xb8\x9a\xbf\xb8\x9a\xbf\xb8\x9a\xbc\x3c\x9a\x0a\x0b\x0c\x0d',
            'expected': b''.join((b'\x9a'*996, b'\x0a\x0b\x0c\x0d'))
        },
        'old_then_new': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'input': b'\x78\x00\x08\x00\x24\xa0\xa1\xa2\xa3',
            'expected': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xa1\xa2\xa3',
        },
        'old_long_then_new': {
            'init_args': {'line_size': 500, 'init_value': b'\xf0'},
            'input': b''.join((
                b'\xbf\xb8\x00\xbe\xa8\x00',
                b'\x9f\x3a\x1a\x2a\x3a\x4a\x5a\x6a\x7a\x41'
            )),
            'expected': b''.join((
                b'\x00'*500,
                b'\x00'*250, b'\x1a\x2a\x3a\x4a\x5a\x6a\x7a',
                b'\x00'*243
            )),
        },
        'old_then_repeat': {
            'init_args': {'line_size': LINE_SIZE, 'init_value': b'\xf0'},
            'input': b'\x78\x00\x08\x00\x64\xa0',
            'expected': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xa0\xa0\xa0',
        },
        'eol_full_line': {
            'init_args': {'line_size': 8, 'init_value': b'\xf0'},
            'input': b'\xe4\x9a\xa0\xa1\xa2\xa3\x41',
            'expected': b'\x9a\x9a\x9a\x9a\xa0\xa1\xa2\xa3'*2
        },
        'eol_half_line': {
            'init_args': {'line_size': 8, 'init_value': b'\xf0'},
            'input': b'\xf9\x00\x00\x60\xff\x41',
            'expected': b'\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00'
        },
        'eol_half_line_2x': {
            'init_args': {'line_size': 8, 'init_value': b'\xf0'},
            'input': b'\xf9\x00\x00\x60\xff\x41\x41',
            'expected': b''.join((b'\x00'*8, b'\xff\xff\xff\xff\x00\x00\x00\x00'*2))
        }
    }

    def test_decode(self):
        for k in self.DECODE_CASES.keys():
            testdata = self.DECODE_CASES[k]
            with self.subTest(test=k, input=testdata['input']):
                sd = scoa.SCoADecoder(**testdata['init_args'])
                samp = bytes(sd.decode(iter(testdata['input'])))
                self.assertEqual(samp, testdata['expected'])

    def test_decode_buffer_full_line(self):
        """The buffer must hold a copy of the previous line"""
        sd = scoa.SCoADecoder(8, init_value=b'\xf0')
        #biter = (x for x in b'\x60\x00\x20\x90\x91\x92\x93') # alt. version
        biter = (x for x in b'\xe4\x00\x90\x91\x92\x93') 
        [x for x in sd.decode(biter)]
        self.assertEqual(bytes(sd._buffer), b'\x00\x00\x00\x00\x90\x91\x92\x93')

    def test_decode_buffer_overflow(self):
        """Excess bytes must overflow onto the next line"""
        sd = scoa.SCoADecoder(8, init_value=b'\xf0')
        biter = iter(b'\x78\x90\x50\x91') # 0x90 seven times, 0x91 twice
        out = [x for x in sd.decode(biter)]
        self.assertEqual(bytes(out), b'\x90\x90\x90\x90\x90\x90\x90\x91\x91')
        self.assertEqual(bytes(sd._buffer), b'\x91\x90\x90\x90\x90\x90\x90\x91')

