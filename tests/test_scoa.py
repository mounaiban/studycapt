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

from io import BytesIO
from unittest import TestCase
import scoa

LINE_SIZE = 8
LINE_SIZE_LONG = 1000

class ScoaDecoder2Tests(TestCase):
    BPL = 16
    BPL_LONG = 877  # approx. A3 short side width @ 600dpi

    def test_exe_single_op(self):
        # tests for _exe()
        CASES = {
            'copy_then_raw_one': {
                'args': {
                    'count_cp':1,
                    'count_rep':0,
                    'count_raw':1,
                    'ib': iter(b'\x01'),
                        # PROTIP: op has been stripped/consumed
                        # from ib by decode()
                },
                'init_buf': b'\x9a' * self.BPL, # init state of _buffer
                'expected_out': (0, 2),
                'expected_buf': b''.join((
                    b'\x9a\x01',
                    b'\x9a' * (self.BPL-2)
                ))
            },
            'copy_then_raw_max': {
                'args': {
                    'count_cp':7,
                    'count_rep':0,
                    'count_raw':7,
                    'ib': iter(b'\x01\x02\x03\x04\x05\x06\x07'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 14),
                'expected_buf': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x01',
                    b'\x02\x03\x04\x05\x06\x07\x9a\x9a',
                ))
            },
            'copy_then_repeat_one': {
                'args': {
                    'count_cp':1,
                    'count_rep':1,
                    'count_raw':0,
                    'ib': iter(b'\x01'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 2),
                'expected_buf': b''.join((
                    b'\x9a\x01',
                    b'\x9a' * (self.BPL-2)
                ))
            },
            'repeat_then_raw_max': {
                'args': {
                    'count_cp':0,
                    'count_rep':7,
                    'count_raw':7,
                    'ib': iter(b'\x01\x02\x03\x04\x05\x06\x07\x08'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 14),
                'expected_buf': b''.join((
                    b'\x01\x01\x01\x01\x01\x01\x01\x02',
                    b'\x03\x04\x05\x06\x07\x08\x9a\x9a',
                ))
            },
            'all_5': {
                # Hypothetical case for testing order of
                # operations only. No known SCoA opcode has
                # all three operations.
                'args': {
                    'count_cp':5,
                    'count_rep':5,
                    'count_raw':5,
                    'ib': iter(b'\x01\x02\x03\x04\x05\x06'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 15),
                'expected_buf': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x01\x01\x01',
                    b'\x01\x01\x02\x03\x04\x05\x06\x9a',
                ))
            },
            'all_5_trailing_bytes': {
                # Hypothetical case
                'args': {
                    'count_cp':5,
                    'count_rep':5,
                    'count_raw':5,
                    'ib': iter(b'\x01\x02\x03\x04\x05\x06\x67\x67'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 15),
                'expected_buf': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x01\x01\x01',
                    b'\x01\x01\x02\x03\x04\x05\x06\x9a',
                ))
            },
            'all_zero': {
                'args': {
                    'count_cp':0,
                    'count_rep':0,
                    'count_raw':0,
                    'ib': iter(b''),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 0),
                'expected_buf': b'\x9a' * self.BPL
            },
            'all_zero_trailing_bytes': {
                'args': {
                    'count_cp':0,
                    'count_rep':0,
                    'count_raw':0,
                    'ib': iter(b'\x01\x02\x03\x04\x05\x06\x07\x08'),
                },
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 0),
                'expected_buf': b'\x9a' * self.BPL
            },
        }
        for c in CASES.keys():
            with self.subTest(c):
                specs = CASES[c]
                decoder = scoa.SCoADecoder2(self.BPL)
                decoder._buffer = BytesIO(specs['init_buf'])
                out = decoder._exe(**specs['args'])
                bbytes = decoder._buffer.getbuffer().tobytes()
                self.assertEqual(out, specs['expected_out'])
                self.assertEqual(bbytes, specs['expected_buf'])
                decoder._buffer.getbuffer().release()

    def test_exe_multi_op(self):
        # tests for _exe() handling successive calls

        CASES = {
            'copy_repeat_copy_raw_same_line': {
                'args_1': {
                    'count_cp':3,
                    'count_rep':3,
                    'count_raw':0,
                    'ib': iter(b'\x01'),
                }, # _exe() first call
                'args_2': {
                    'count_cp':5,
                    'count_rep':0,
                    'count_raw':5,
                    'ib': iter(b'\x02\x03\x04\x05\x06'),
                }, # _exe() 2nd call whose results are to be checked
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (6, 10),
                'expected_buf': b''.join((
                    b'\x9a\x9a\x9a\x01\x01\x01\x9a\x9a',
                    b'\x9a\x9a\x9a\x02\x03\x04\x05\x06',
                ))
            },
            'copy_repeat_copy_raw_two_lines': {
                'args_1': {
                    'count_cp':9,
                    'count_rep':7,
                    'count_raw':0,
                    'ib': iter(b'\x01'),
                }, # _exe() first call
                'args_2': {
                    'count_cp':11,
                    'count_rep':0,
                    'count_raw':5,
                    'ib': iter(b'\x02\x03\x04\x05\x06'),
                }, # _exe() 2nd call whose results are to be checked
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 16),
                'expected_buf': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x9a\x01\x01\x02\x03\x04\x05\x06',
                ))
            },
            'no_op_repeat_raw_half_line': {
                'args_1': {
                    'count_cp':0,
                    'count_rep':0,
                    'count_raw':0,
                    'ib': None,
                }, # _exe() first call
                'args_2': {
                    'count_cp':0,
                    'count_rep':5,
                    'count_raw':3,
                    'ib': iter(b'\x01\x02\x03\x04'),
                }, # _exe() 2nd call whose results are to be checked
                'init_buf': b'\x9a' * self.BPL,
                'expected_out': (0, 8),
                'expected_buf': b''.join((
                    b'\x01\x01\x01\x01\x01\x02\x03\x04',
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                ))
            },
        }
        for c in CASES.keys():
            with self.subTest(c):
                specs = CASES[c]
                decoder = scoa.SCoADecoder2(self.BPL)
                decoder._buffer = BytesIO(specs['init_buf'])
                decoder._exe(**specs['args_1'])
                out = decoder._exe(**specs['args_2'])
                bbytes = decoder._buffer.getbuffer().tobytes()
                self.assertEqual(bbytes, specs['expected_buf'])
                self.assertEqual(out, specs['expected_out'])
                decoder._buffer.getbuffer().release()

    def test_exe_overflow_single_op(self):
        decoder = scoa.SCoADecoder2(16)
        with self.assertRaises(Exception):
            decoder._exe(
                7,7,7,iter(b'\xff\x00\x00\x00\x00\x00\x00\x00')
            ) # + 21B

    def test_exe_overflow_multi_op(self):
        decoder = scoa.SCoADecoder2(16)  # line size: 16B
        with self.assertRaises(Exception):
            decoder._exe(7,7,0, iter(b'\xff')) # 14B
            decoder._exe(2,1,0, iter(b'\xff')) # +3B

    def test_decode_single_op(self):
        CASES = {
            'decode_copy_raw_one': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x09\x02',
                'expected': b'\x9a\x02'
            }, # 1cp + 1raw
            'decode_copy_one_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x11\x02\x03',
                'expected': b'\x9a\x02\x03'
            },
            'decode_copy_4_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x14\x02\x03',
                'expected': b'\x9a\x9a\x9a\x9a\x02\x03'
            },
            'decode_copy_5_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x15\x02\x03',
                'expected': b'\x9a\x9a\x9a\x9a\x9a\x02\x03'
            },
            'decode_copy_6_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x16\x02\x03',
                'expected': b'\x9a\x9a\x9a\x9a\x9a\x9a\x02\x03'
            },
            'decode_copy_7_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x17\x02\x03',
                'expected': b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x02\x03'
            },
            'decode_copy_raw_max': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x3f\x02\x03\x04\x05\x06\x07\x08',
                'expected': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x02\x03\x04\x05\x06\x07\x08'
                )),
            }, # 7cp + 7raw
            'decode_copy_zero_raw_2': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x10\x02\x03',
                'expected': b'\x02\x03',
            }, # 0cp + 2raw
            'decode_copy_repeat_one': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x49\x01',
                'expected': b'\x9a\x01'
            }, # 1cp + 1rep
            'decode_copy_repeat_max': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x7f\x01',
                'expected': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x01\x01\x01\x01\x01\x01\x01'
                )),
            }, # 7cp + 7rep
            'decode_repeat_then_raw_one': {
                'bpl': self.BPL,
                'input': b'\xc9\x01\x02',
                'expected': b'\x01\x02',
            }, # 1raw + 1rep
            'decode_repeat_then_raw_max': {
                'bpl': self.BPL,
                'input': b'\xff\x01\x02\x03\x04\x05\x06\x07\x08',
                'expected': b''.join((
                    b'\x01\x01\x01\x01\x01\x01\x01',
                    b'\x02\x03\x04\x05\x06\x07\x08'
                )),
            }, # 7raw + 7rep
            'decode_long_copy_raw_min': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x81\x08\x02',
                'expected': b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x02'
            }, # 8cp + 1raw
            'decode_long_copy_repeat_min': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x81\x48\x01',
                'expected': b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x01'
            }, # 8cp + 1rep
            'decode_long_repeat_raw_min': {
                'bpl': self.BPL,
                'input': b'\xa1\x01\x01\x02',
                'expected': b'\x01\x01\x01\x01\x01\x01\x01\x01\x02'
            }, # 8rep + 1raw
            'decode_repeat_long_raw_min': {
                'bpl': self.BPL,
                'input':b'\xa1\x48\x01\x02\x03\x04\x05\x06\x07\x08\x09',
                'expected': b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'
            }, # 1rep + 8raw
            'decode_copy_long_repeat_min': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\xa1\x81\x01',
                'expected': b'\x9a\x01\x01\x01\x01\x01\x01\x01\x01'
            }, # 1cp + 8rep
            'decode_copy_long_raw_min':{
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\xa1\xc1\x02\x03\x04\x05\x06\x07\x08\x09',
                'expected': b'\x9a\x02\x03\x04\x05\x06\x07\x08\x09'
            }, # 1cp + 8raw
            'decode_long_copy_long_repeat_min': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x81\xa1\x80\x01',
                'expected': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x01\x01\x01\x01\x01\x01\x01\x01'
                )),
            }, # 8cp + 8rep
            'decode_long_copy_long_raw': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input':b'\x81\xa1\xc0\x02\x03\x04\x05\x06\x07\x08\x09',
                'expected': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x02\x03\x04\x05\x06\x07\x08\x09'
                )),
            }, # 8cp + 8raw
            'decode_nop': {
                'bpl': self.BPL,
                'input':b'\x40',
                'expected': b'',
            },
            'decode_eol': {
                'bpl': self.BPL,
                'init': b'\x9a' * self.BPL,
                'input': b'\x41',
                'expected': b''.join((
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                    b'\x9a\x9a\x9a\x9a\x9a\x9a\x9a\x9a',
                )),
            },
            'decode_extend_long_copy_raw_min': {
                'bpl': self.BPL_LONG,
                'init': b'\x9a' * self.BPL_LONG,
                'input': b'\x9f\x81\x08\x02',
                'expected': b''.join((
                    b'\x9a' * 256,
                    b'\x02',
                )),
            }, # 248cp + 8cp + 1raw
            'decode_extend_2_long_copy_raw_min': {
                'bpl': self.BPL_LONG,
                'init': b'\x9a' * self.BPL_LONG,
                'input': b'\x9f\x9f\x81\x08\x02',
                'expected': b''.join((
                    b'\x9a' * 504,
                    b'\x02',
                )),
            }, # 496cp + 8cp + 1raw
        }
        for c in CASES.keys():
            with self.subTest(c):
                spec = CASES[c]
                decoder = scoa.SCoADecoder2(spec['bpl'])
                init = spec.get('init')
                if init: decoder._buffer = BytesIO(spec['init'])
                ib = iter(spec['input'])
                out = b''.join(decoder.decode(ib))
                self.assertEqual(out, spec['expected'])

    def test_decode_multi_op(self):
        # two inputs, two outputs
        pass

    def test_decode_input_offset(self):
        CASES = {
            'no_offset_1B_op_1B_data': {
                'init': b'\x9a' * self.BPL,
                'args': {
                    'ib': iter(b'\x7f\x01'),
                    'in_off': None,
                },
                'expected': 1
            }, # cp+rep
            'no_offset_1B_op_7B_data': {
                'init': b'\x9a' * self.BPL,
                'args': {
                    'ib': iter(b'\x3f\x02\x03\x04\x05\x06\x07\x08'),
                    'in_off': None,
                },
                'expected': 7
            }, # cp+rep
            'no_offset_3B_op_8B_data': {
                'init': b'\x9a' * self.BPL,
                'args': {
                    'ib': iter(b'\x81\xa1\xc0abcdefgh')
                },
                'expected': 10,
            }, # 8cp + 8raw
            'offset_1B_op_1B_data': {
                'init': b'\x9a' * self.BPL,
                'args': {
                    'ib': iter(b'\x7f\x01'),
                    'in_off': 127,
                },
                'expected': 128
            }, # cp+rep
            'offset_3B_op_8B_data': {
                'init': b'\x9a' * self.BPL,
                'args': {
                    'ib': iter(b'\x81\xa1\xc0abcdefgh'),
                    'in_off': 300
                },
                'expected': 310,
            }, # 8cp + 8raw
        }
        for k in CASES.keys():
            spec = CASES[k]
            with self.subTest(k):
                decoder = scoa.SCoADecoder2(self.BPL)
                init = spec.get('init')
                if init: decoder._buffer = BytesIO(init)
                tuple(decoder.decode(**spec['args']))
                expected = spec['expected']
                self.assertEqual(decoder.input_offset, expected)

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

