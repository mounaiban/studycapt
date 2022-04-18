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
from sample_blots import _p4_new_raster, _p4_set_pixel

class SampleCanvasTests(TestCase):

    def test_p4_new_raster(self):
        test_cases = (
            ({'w': 8, 'h': 8}, [0x0,]*8),
            ({'w': 9, 'h': 8}, [0x0,]*16),
        ) # format: (args, expected_output)
        for a, r in test_cases:
            with self.subTest(a=a, r=r):
                self.assertEqual(_p4_new_raster(**a), r)

    def test_p4_set_pixel_corners(self):
        test_cases = (
            ({'w': 8, 'h': 8}, [0x81, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x81]),
            ({'w': 5, 'h': 4}, [0x88, 0x0, 0x0, 0x88]),
            ({'w': 4, 'h': 5}, [0x90, 0x0, 0x0, 0x0, 0x90]),
        )
        for a, r in test_cases:
            with self.subTest(a=a):
                raster = _p4_new_raster(**a)
                _p4_set_pixel(raster, a['w'], 0, 0)
                _p4_set_pixel(raster, a['w'], 0, a['h']-1)
                _p4_set_pixel(raster, a['w'], a['w']-1, 0)
                _p4_set_pixel(raster, a['w'], a['w']-1, a['h']-1)
                self.assertEqual(raster, r)

