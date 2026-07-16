"""
Raster Dump (rasterdump.py) Unit Tests
"""
# Written by Moses Chong
# First edition 2026/05/26
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
import rasterdump

class RasterDumpTests(TestCase):
    # RasterDump 1BPP Test Cases

    def test_clear(self):
        raster = rasterdump.RasterDump(w=8, h=8)
        raster.put_raster_bytes(b'\xDE\xAD\xBE\xEF')
        raster.clear()
        out = raster.get_raster()
        self.assertEqual(out, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(raster._raster_position(), 0)

    def test_clear_then_put_bytes(self):
        raster = rasterdump.RasterDump(w=8, h=8)
        raster.put_raster_bytes(b'\x42', count=8)
        raster.clear()
        raster.put_raster_bytes(b'\x67', count=4)
        out = raster.get_raster()
        self.assertEqual(out, b'\x67\x67\x67\x67\x00\x00\x00\x00')
        self.assertEqual(raster._raster_position(), 4)

    def test_draw_position(self):
        # tests on 32x32x1bpp raster
        CASES = {
            'pos_init': {'bytes': 0, 'expected': (0,0)},
            'pos_mid_row_zero': {'bytes': 2, 'expected': (16,0)},
            'pos_end_row_zero': {'bytes': 4, 'expected': (0,1)},
            'pos_raster_middle': {'bytes': 62, 'expected': (16,15)},
            'pos_raster_end': {'bytes':128, 'expected':(31,31)}
        }
        for t in CASES.keys():
            specs = CASES[t]
            with self.subTest(t):
                raster = rasterdump.RasterDump(w=32, h=32)
                n = specs['bytes']
                raster.put_raster_bytes(b'\x67' * n)
                coords = raster.draw_position()
                expected = specs['expected']
                self.assertEqual(coords, expected)

    def test_get_raster(self):
        # tests for get_raster()
        # test format description
        CASES = {
            # outer dicts: test cases
            'full_1bpp': {
                # inner dicts: args for tested functions & expectations
                'init' : {'w': 8, 'h': 8, 'pad': b'\x00'}, # __init__()
                'put_raster_bytes': {
                    'b': b'\x00\x66\xFF\x7C\x38\x10\x00\x00',
                    'count': 1,
                }, # put_raster_bytes()
                'expected': b'\x00\x66\xFF\x7C\x38\x10\x00\x00',
                   # expected output
            },
            'partial_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\x00'},
                'put_raster_bytes': { 'b': b'\x0A\x0A\x0A','count': 1},
                'expected': b'\x0A\x0A\x0A\x00\x00\x00\x00\x00'
            },
            'empty_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\x00'},
                'put_raster_bytes': { 'b': b'','count': 0},
                'expected': b'\x00\x00\x00\x00\x00\x00\x00\x00'
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDump(**specs['init'])
            raster.put_raster_bytes(**specs['put_raster_bytes'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

    def test_init_with_pad(self):
        # tests for RasterDump custom padding
        CASES = {
            'pad_deadbeef_empty_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xDE\xAD\xBE\xEF'},
                'put_raster_bytes': {'b': b'', 'count': 0},
                'expected': b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF',
            }, # pad with aligned number of bytes
            'pad_deadbeef_partial_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xDE\xAD\xBE\xEF'},
                'put_raster_bytes': {'b': b'\xFF\xFF\xFF\xFF', 'count': 1},
                'expected': b'\xFF\xFF\xFF\xFF\xDE\xAD\xBE\xEF',
            }, # pad with aligned number of bytes
            'pad_deadbeef_full_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xDE\xAD\xBE\xEF'},
                'put_raster_bytes': {
                    'b': b'\x00\x00\x00\x00\x00\x00\x00\x00', 'count': 1
                },
                'expected': b'\x00\x00\x00\x00\x00\x00\x00\x00',
            }, # pad with aligned number of bytes
            'pad_coffee_empty_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xC0\xFF\xEE'},
                'put_raster_bytes': { 'b': b'','count': 0},
                'expected': b'\xC0\xFF\xEE\xC0\xFF\xEE\xC0\xFF'
            }, # pad with non-aligned number of bytes
            'pad_coffee_partial_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xC0\xFF\xEE'},
                'put_raster_bytes': { 'b': b'\x00\x00\x00','count': 1},
                'expected': b'\x00\x00\x00\xC0\xFF\xEE\xC0\xFF'
            }, # pad with non-aligned number of bytes
            'pad_coffee_full_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xC0\xFF\xEE'},
                'put_raster_bytes': {
                    'b': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF','count': 1
                },
                'expected': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            }, # pad with non-aligned number of bytes
            'pad_ff_empty_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': { 'b': b'','count': 0},
                'expected': b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            }, # pad with single byte pattern (also aligned)
            'pad_ff_partial_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\x12\x34\x56\x78','count':1},
                'expected': b'\x12\x34\x56\x78\xFF\xFF\xFF\xFF'
            }, # pad with single byte pattern (also aligned)
            'pad_ff_full_1bpp': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {
                    'b': b'\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD','count': 1
                },
                'expected': b'\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD'
            }, # pad with single byte pattern (also aligned)

            # testing with default \x00 padding already covered
            # in test_get_raster()
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDump(**specs['init'])
            raster.put_raster_bytes(**specs['put_raster_bytes'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

    def test_get_row_byte_size(self):
        # tests for get_row_byte_size()
        CASES = {
            '1px_wide_row_size_1bpp': {
                'init': {'w':1, 'h':1024},
                'expected': 1
            }, # not aligned
            'aligned_row_size_1bpp': {
                'init': {'w':16, 'h':180},
                'expected': 2
            },
            'non_aligned_row_size_2px_1bpp': {
                'init': {'w':2, 'h':1024},
                'expected': 1
            },
            'non_aligned_row_size_17px_1bpp': {
                'init': {'w':17, 'h':1024},
                'expected': 3
            },
            'non_aligned_row_size_23px_1bpp': {
                'init': {'w':23, 'h':1024},
                'expected': 3
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDump(**specs['init'])
            out = raster.get_row_byte_size()
            self.assertEqual(out, specs['expected'], t)

    def tests_put_raster_bytes(self):
        # tests for put_raster_bytes()
        CASES = {
            'multi_count_partial': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\xAA\xBB\xCC','count':2},
                'expected': b'\xAA\xBB\xCC\xAA\xBB\xCC\xFF\xFF'
            },
            'multi_count_full': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {
                    'b':b'\xAA\xBB\xCC\xDD\x11\x22\x33\x44','count':1
                },
                'expected': b'\xAA\xBB\xCC\xDD\x11\x22\x33\x44',
            },
            'multi_count_overflow': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\xAA\xBB\xCC','count':3},
                'expected': b'\xAA\xBB\xCC\xAA\xBB\xCC\xAA\xBB'
            },
            'multi_count_xtreme_overflow': {
                'init' : {'w': 8, 'h': 8, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\xAA\xBB\xCC','count':9999},
                'expected': b'\xAA\xBB\xCC\xAA\xBB\xCC\xAA\xBB'
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDump(**specs['init'])
            raster.put_raster_bytes(**specs['put_raster_bytes'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

        # tests for zero-count empty & single-count empty, partial and
        # full rasters already covered in test_init_with_pad() and
        # test_get_raster()

class RasterDumpBGR888Tests(TestCase):
    def test_put_pixels(self):
        raster = rasterdump.RasterDumpBGR888(w=2, h=2)
        raster.put_pixels(0xFF, 0x00, 0x80, count=2)
        out = raster.get_raster()
        expected = b'\x80\x00\xFF\x80\x00\xFF\x00\x00\x00\x00\x00\x00'
        self.assertEqual(out, expected)

class RasterDumpRGB888Tests(TestCase):
    # RasterDump 24BPP Test Cases

    def test_clear(self):
        raster = rasterdump.RasterDumpRGB888(w=2, h=2)
        raster.put_raster_bytes(b'\xDE\xAD\xBE')
        raster.clear()
        out = raster.get_raster()
        self.assertEqual(
            out, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )
        self.assertEqual(raster._raster_position(), 0)

    def test_get_raster(self):
        CASES = {
            'full_24bpp': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\x00\xFF\x00'},
                'put_raster_bytes': {
                    'b': b'\xFF\xFF\x00\xFF\xFF\x00\x00\x00\xFF\x00\x00\xFF',
                    'count': 1,
                },
                'expected': b'\xFF\xFF\x00\xFF\xFF\x00\x00\x00\xFF\x00\x00\xFF',
            },
            'partial_24bpp': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\x00\xFF\x00'},
                'put_raster_bytes': {
                    'b': b'\xFF\xFF\x00\xFF\xFF\x00',
                    'count': 1
                },
                'expected': b'\xFF\xFF\x00\xFF\xFF\x00\x00\xFF\x00\x00\xFF\x00'
            },
            'empty_24bpp': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\x00\xFF\x00'},
                'put_raster_bytes': { 'b': b'','count': 0},
                'expected': b'\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00'
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDumpRGB888(**specs['init'])
            raster.put_raster_bytes(**specs['put_raster_bytes'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

    def test_get_row_byte_size(self):
        # tests for get_row_byte_size()
        CASES = {
            '1px_wide_row_size_24bpp': {
                'init': {'w':1, 'h':1024},
                'expected': 3
            },
            'aligned_row_size_24bpp': {
                'init': {'w':180, 'h':180},
                'expected': 540
            }
        } # 24bpp images are always byte-aligned
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDumpRGB888(**specs['init'])
            out = raster.get_row_byte_size()
            self.assertEqual(out, specs['expected'], t)

    def tests_put_raster_bytes(self):
        # tests for put_raster_bytes()
        CASES = {
            'multi_count_partial': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF\xFF\xFF'},
                'put_pixels': {'r':128,'g':255,'b':128,'count':2},
                'expected':
                    b'\x80\xEE\x80\x80\xEE\x80\xFF\xFF\xFF\xFF\xFF\xFF'
            },
            'multi_count_full': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_pixels': {'r':255, 'g':0, 'b':0, 'count':4},
                'expected':
                    b'\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00',
            },
            'multi_count_overflow': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_pixels': {'r':128, 'g': 255, 'b':0 ,'count':6},
                'expected':
                    b'\x80\xFF\x00\x80\xFF\x00\x80\xFF\x00\x80\xFF\x00'
            },
            'multi_count_xtreme_overflow': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_pixels': {'r':128, 'g': 255, 'b':0 ,'count':9999},
                'expected':
                    b'\x80\xFF\x00\x80\xFF\x00\x80\xFF\x00\x80\xFF\x00'
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDumpRGB888(**specs['init'])
            raster.put_pixels(**specs['put_pixels'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

    def tests_put_raster_bytes(self):
        # tests for put_raster_bytes()
        CASES = {
            'multi_count_partial': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF\xFF\xFF'},
                'put_raster_bytes': {'b':b'\xEE\x00\xEE','count':2},
                'expected':
                    b'\xEE\x00\xEE\xEE\x00\xEE\xFF\xFF\xFF\xFF\xFF\xFF'
            },
            'multi_count_full': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\x00\xCC\x00','count':4},
                'expected':
                    b'\x00\xCC\x00\x00\xCC\x00\x00\xCC\x00\x00\xCC\x00',
            },
            'multi_count_overflow': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\xEE\xDD\x00','count':6},
                'expected':
                    b'\xEE\xDD\x00\xEE\xDD\x00\xEE\xDD\x00\xEE\xDD\x00'
            },
            'multi_count_overflow': {
                'init' : {'w': 2, 'h': 2, 'pad': b'\xFF'},
                'put_raster_bytes': {'b':b'\xEE\xDD\x00','count':9999},
                'expected':
                    b'\xEE\xDD\x00\xEE\xDD\x00\xEE\xDD\x00\xEE\xDD\x00'
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDumpRGB888(**specs['init'])
            raster.put_raster_bytes(**specs['put_raster_bytes'])
            out = raster.get_raster()
            self.assertEqual(out, specs['expected'], t)

        # tests for zero-count empty & single-count empty, partial and
        # full rasters already covered in test_init_with_pad() and
        # test_get_raster()

class BMPWriterTest(TestCase):

    def test_bmp_row_pad_size_1bpp(self):
        CASES = {
            'bmp_row_aligned_1bpp': {
                'init': {'w':32, 'h':128},
                'expected': 0
            },
            'bmp_row_non_aligned_33px_1bpp': {
                'init': {'w':33, 'h':128},
                'expected': 3
            },
            'bmp_row_non_aligned_35px_1bpp': {
                'init': {'w':35, 'h':128},
                'expected': 3
            },
            'bmp_row_non_aligned_40px_1bpp': {
                'init': {'w':40, 'h':128},
                'expected': 3
            },
            'bmp_row_non_aligned_42px_1bpp': {
                'init': {'w':42, 'h':128},
                'expected': 2
            },
            'bmp_row_non_aligned_47px_1bpp': {
                'init': {'w':47, 'h':128},
                'expected': 2
            },
            'bmp_row_non_aligned_48px_1bpp': {
                'init': {'w':48, 'h':128},
                'expected': 2
            },
            'bmp_row_non_aligned_48px_1bpp': {
                'init': {'w':50, 'h':128},
                'expected': 1
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDump(**specs['init'])
            writer = rasterdump.BMPWriter(raster, '.rasterdump_test')
            out = writer._bmp_row_pad_size()
            self.assertEqual(out, specs['expected'])

    def test_bmp_row_pad_size_24bpp(self):
        CASES = {
            'bmp_row_aligned_24bpp': {
                'init': {'w':80, 'h':25},
                'expected': 0
            },
            'bmp_row_non_aligned_81px_24bpp': {
                'init': {'w':81, 'h':25},
                'expected': 1
            },
            'bmp_row_non_aligned_82px_24bpp': {
                'init': {'w':82, 'h':25},
                'expected': 2
            },
            'bmp_row_non_aligned_83px_24bpp': {
                'init': {'w':83, 'h':25},
                'expected': 3
            },
        }
        for t in CASES.keys():
            specs = CASES[t]
            raster = rasterdump.RasterDumpRGB888(**specs['init'])
            writer = rasterdump.BMPWriter(raster, '.rasterdump_test')
            out = writer._bmp_row_pad_size()
            self.assertEqual(out, specs['expected'])

class HelperTests(TestCase):
    def test_value_to_bytes(self):
        # tests for test_value_to_bytes()
        CASES = {
            'neg_min_odd_bytes': {
                'args': {'value': -1, 'size': 3},
                'expected': b'\xFF\xFF\xFF'
            },
            'neg_max_odd_bytes': {
                'args': {'value': -8388608, 'size': 3},
                'expected': b'\x00\x00\x80'
            },
            'pos_max_odd_bytes': {
                'args': {'value': 16777215, 'size': 3},
                'expected': b'\xFF\xFF\xFF'
            },
           'pos_min_odd_bytes': {
                'args': {'value': 1, 'size': 3},
                'expected': b'\x01\x00\x00'
            },
           'zero_odd_bytes': {
               'args': {'value': 0, 'size': 3},
               'expected': b'\x00\x00\x00'
            },
           'mid_even_bytes': {
               'args': {'value': 54, 'size': 4},
               'expected': b'\x36\x00\x00\x00'
            }
        }
        for t in CASES.keys():
            specs = CASES[t]
            args = specs['args']
            out = rasterdump.value_to_bytes(**args)
            self.assertEqual(out, specs['expected'])
