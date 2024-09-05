"""
Quick and Dirty Blob Visualiser

Interpret a blob as pixels for a raster image
"""
# Copyright (C) 2024 Moses Chong
#
# Licensed under the GNU General Public License Version 3
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# SPDX-License-Identifier: GPL-3.0-or-later

from itertools import chain, repeat
from math import ceil

def _intble_iter(v, l):
    """
    Integer as Bytes in Little Endian Iterator:
    Convert Python integer v to a litte-endian byte array
    of length l. Yield one byte at a time as an iter.
    """
    if v == 0:
        for i in range(l): yield 0
    else:
        vmax = 2**(l*8)-1
        if v > vmax:
            raise ValueError(f"highest value for {l} byte uint is {vmax}")
        for i in range(1, l+1):
            yield (v & (2**(i*8)-1)) >> (i-1)*8

class BlobPic:
    ACCEPTED_BPPS = [1, 8, 24]

    def __init__(self, w, h, blob, **kwargs):
        # blob: raw pixel data
        # bpp: bits per pixel
        # res_x and res_y are not really important for now
        # TODO: only 1-bit, Gray 8 and RGB 24 are supported
        self.blob = blob
        self.bpp = kwargs.get('bpp', 1) # bits per pixel
        self.h = int(h)
        self.w = int(w)
        self.res_x = kwargs.get('res_x', 600) # horiz. resolution
        self.res_y = kwargs.get('res_y', 600) # vert. resolution

        if self.bpp not in self.ACCEPTED_BPPS:
            raise ValueError(f"valid values of bpp are: {self.ACCEPTED_BPPS}")

    def _bmp_color_entries(self):
        """Return the colour table for a BMP file"""
         # BMP colours seems to be stored as BGRA,
         # or ARGB little-endian
        if self.bpp == 1:
            # one-bit black & white, or ink and paper
            return (
                b'\xFF\xF0\x00\xFF',
                b'\xC8\xEE\xEE\xFF',
            ) # off-white background
        elif self.bpp == 8:
            # eight-bit greyscale
            return (bytes((x, max(x,2), max(x,20),255)) for x in range(256))
        else: return () # no index, pixel-by-pixel RGB

    def _bmp_nce(self):
        """Return number of palette/colour table entries"""
        if self.bpp <= 8: return 2**self.bpp
        else: return 0

    def _px_bytes(self, n):
        """Return the expected number of bytes for n pixels"""
        if self.bpp < 8: return ceil(n / (8//self.bpp))
        else: return n * ceil(self.bpp / 8)

    def _bmp_wpad(self):
        """
        Return the number of bytes of padding per pixel row
        needed for a BMP image
        """
        return ceil(self._px_bytes(self.w)/4)*4 - self._px_bytes(self.w)

    def _bmp_row_iter(self):
        """
        Return an iter yielding the image data for a BMP image,
        row-by-row with padding. Rows are yielded as bytes objects,
        aligned to a multiple of four bytes.
        """
        img = chain(iter(self.blob), repeat(0))
        for r in range(self.h):
            yield bytes(chain(
                (next(img) for i in range(self._px_bytes(self.w))),
                (0 for j in range(self._bmp_wpad())),
            ))

    def bmp(self):
        """
        Returns bytes for a Microsoft BMP Image, using the
        1992 standard (BITMAPINFOHEADER)
        """
        MAGIC = b'BM'
        INFO_A = b'\x00\x00'
        INFO_B = b'\x00\x00'
        # Using 1992 BMP (BITMAPINFOHEADER)
        #  1987 BMP (BITMAPCOREHEADER) would have worked, but I
        #  was too lazy to flip the rows to deal with the
        #  bottom-to-top row order
        HEADER_SIZE = 14 # always 14
        INFO_SIZE = _intble_iter(40, 4)
        bmp_width = _intble_iter(self.w, 4)
        bmp_height = _intble_iter(-self.h, 4)
        COLOR_PLANES = b'\x01\x00'
        bmp_bpp = _intble_iter(self.bpp, 2)
        COMPRESSION = b'\x00\x00\x00\x00' # BI_RGB
        BLOB_SIZE = b'\x00\x00\x00\x00'
        res_x = _intble_iter(self.res_x, 4)
        res_y = _intble_iter(self.res_y, 4)
        N_ENTRIES = _intble_iter(self._bmp_nce(), 4) # num. of entries
        COLOR_ENTRIES = self._bmp_color_entries()    # actual entries
        IMPORTANT_COLORS = _intble_iter(0, 4)
        ### late calc vars
        binfo = bytes(chain(INFO_SIZE, bmp_width, bmp_height, COLOR_PLANES,
            bmp_bpp, COMPRESSION, BLOB_SIZE, res_x, res_y, N_ENTRIES,
            *COLOR_ENTRIES, IMPORTANT_COLORS
        ))
        boff = len(binfo)+HEADER_SIZE # blob offset
        img = b''.join(self._bmp_row_iter())
        rowsize = (self._bmp_wpad() + self._px_bytes(self.w))
        bmpsize = rowsize*self.h
        allsize = _intble_iter(bmpsize+len(binfo)+HEADER_SIZE, 4)
        bhead = bytes(chain(
            MAGIC, allsize, INFO_A, INFO_B, _intble_iter(boff, 4)
        ))
        return b''.join((bhead, binfo, img))

### Test Samples
#### Alignment Checks
test_1bpp_8x8 = BlobPic(8, 8, b'\x00\x42\x00\x00\x00\x00\x42\x00', bpp=1)
test_1bpp_12x12 = BlobPic(
    12,12,b''.join((b'\x00\x00\x40\x20', b'\x00'*16, b'\x40\x20\x00\x00')),bpp=1
)
test_1bpp_32x32 = BlobPic(
    32,32,b''.join((b'\x00'*4,b'\x40',b'\x00'*118,b'\x02',b'\x00'*4)),bpp=1
) # manual RLE FTW
test_8bpp_16x16 = BlobPic(16,16,bytes(range(255,0,-1)),bpp=8)

#### Fill Checks
test_1bpp_32x16_fill = BlobPic(32, 16, bytes(range(12)), bpp=1)
test_8bpp_32x16_fill = BlobPic(32, 16, bytes(range(255,1,-16)), bpp=8)

#### Overflow Checks
test_8bpp_12x10_of = BlobPic(12, 10, bytes(range(255,1,-1)), bpp=8)

#### Fun Stuff
def test_rainbow(w,h):
    hi = 2**24
    pixs = b''.join(bytes(_intble_iter(x,3)) for x in range(0,hi,hi//(w*h)))
    return BlobPic(w,h,pixs,bpp=24)
