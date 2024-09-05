"""
Quick and Dirty Blob Visualiser (blob_pic.py) Unit Tests
"""

from unittest import TestCase
import blob_pic

class HelperFunctionTests(TestCase):
    # _intble_iter() tests
    #
    def test_intble_iter_valid(self):
        INTBLE_ITER_VALID_CASES = {
            'neg_one_byte': {
                'v': -6,
                'l': 1,
                'expected': b'\xfa'
            },
            'neg_multi_byte': {
                'v': -300,
                'l': 2,
                'expected': b'\xd4\xfe'
            },
            'pos_one_byte': {
                'v': 1,
                'l': 1,
                'expected': b'\x01'
            },
            'pos_multi_byte': {
                'v': 260,
                'l': 2,
                'expected': b'\x04\x01'
            },
            'pos_small_multi_byte': {
                'v': 2,
                'l': 3,
                'expected': b'\x02\x00\x00'
            },
            'zero_one_byte': {
                'v': 0,
                'l': 1,
                'expected': b'\x00'
            },
            'zero_multi_byte': {
                'v': 0,
                'l': 5,
                'expected': b'\x00\x00\x00\x00\x00'
            }
        }
        for k in INTBLE_ITER_VALID_CASES.keys():
            with self.subTest(test=k):
                tcase = INTBLE_ITER_VALID_CASES[k] # contains arguments
                expected = tcase.pop('expected')
                result = bytes(blob_pic._intble_iter(**tcase))
                self.assertEqual(result, expected)

class BlobPicTests(TestCase):
    def test_bmp_wpad(self):
        BLOB_PIC_BMP_WPAD_CASES = {
            '1bpp_8x8': {
                'w': 8,
                'h': 8,
                'bpp': 1,
                'expected': 3
            },
            '1bpp_32x32': {
                'w': 32,
                'h': 32,
                'bpp': 1,
                'expected': 0
            },
            '8bpp_9x9': {
                'w': 9,
                'h': 9,
                'bpp': 8,
                'expected': 3
            },
            '8bpp_15x32': {
                'w': 15,
                'h': 32,
                'bpp': 8,
                'expected': 1
            },
            '8bpp_20x20': {
                'w': 20,
                'h': 20,
                'bpp': 8,
                'expected': 0
            },
        }
        for k in BLOB_PIC_BMP_WPAD_CASES.keys():
            with self.subTest(test=k):
                tcase = BLOB_PIC_BMP_WPAD_CASES[k]
                tcase['blob'] = b'\x00'
                expected = tcase.pop('expected')
                pic = blob_pic.BlobPic(**tcase)
                result = pic._bmp_wpad()
                self.assertEqual(result, expected)

    def test_px_bytes(self):
        BLOB_PIC_PX_BYTES_CASES = {
            '1bpp_1px': {
                'n': 8,
                'bpp': 1,
                'expected': 1
            },
            '1bpp_4px': {
                'n': 4,
                'bpp': 1,
                'expected': 1
            },
            '1bpp_13px': {
                'n': 13,
                'bpp': 1,
                'expected': 2
            },
            '1bpp_16px': {
                'n': 16,
                'bpp': 1,
                'expected': 2
            },
            '8bpp_1px': {
                'n': 1,
                'bpp': 8,
                'expected': 1
            },
            '8bpp_3px': {
                'n': 3,
                'bpp': 8,
                'expected': 3
            },
            '8bpp_15px': {
                'n': 15,
                'bpp': 8,
                'expected': 15
            },
            '24bpp_1px': {
                'n': 1,
                'bpp': 24,
                'expected': 3
            },
            '24bpp_13px': {
                'n': 13,
                'bpp': 24,
                'expected': 39
            },
        }
        for k in BLOB_PIC_PX_BYTES_CASES.keys():
            with self.subTest(test=k):
                tcase = BLOB_PIC_PX_BYTES_CASES[k]
                expected = tcase.pop('expected')
                pic = blob_pic.BlobPic(8,8,b'\x00',bpp=tcase['bpp'])
                result = pic._px_bytes(tcase['n'])
                self.assertEqual(result, expected)

