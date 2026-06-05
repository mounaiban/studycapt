"""
Raster Dump

Raster canvas with Netpbm file output support for studying
image compression codecs.

Only 1bpp black-and-white and 24bpp RGB colour formats are
currently supported.

Replaces blob_pic.

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

from colorsys import hls_to_rgb
from io import BytesIO
from itertools import chain, cycle
from math import ceil
from os import access, F_OK

# Helper Functions
def value_to_bytes(value, size):
    """
    Converts value to a little endian byte array representation
    of a specified length (size).

    Value can be of type int or bytes. Negative int's are converted
    as signed, positive as unsigned, while bytes are clipped
    or padded.

    value_to_bytes(512, 4) => b'\\x00\\x02\\x00\\x00'
    value_to_bytes(-8388608, 3) => b'\\x00\\x00\\x80'
    value_to_bytes(b'CAFEBABE', 6) => b'CAFEBA'
    value_to_bytes(b'HI', 8) => b'HI\\x00\\x00\\x00\\x00\\x00\\x00'

    """
    if type(value) is bytes: # bytes: clip excess bytes from left side
        size_diff = len(value) - size
        if size_diff < 0:
            return b''.join((value, b'\x00' * -size_diff))
        else: return value[:size]
    if type(value) is int: # int: convert to (size*8)-bit integer
        if value < 0:
            return int.to_bytes(value, size, 'little', signed=True)
        else: return int.to_bytes(value, size, 'little')
    raise TypeError('value must be bytes or int')

def dict_to_struct(values, spec):
    """
    Convert a dict (values) to a byte array of packed values,
    as specified by a specification dict (spec). Supports
    int's and byte arrays.

    Format and Example
    ==================
    spec = {'format': 5, 'w': 4, 'h': 4}
        # 'format' is 5 bytes, 'h' is 4B, 'w' is 4B
    values = {'w': 7680, 'format': b'AVIF', 'h': 4320}
    dict_to_struct(spec, values) => b'AVIF\\x00\\x00\\x1e\\x00\\x00\\xe0\\x10\\x00\\x00'

    The values appear in the struct in the same order as the specification
    dict. Please note that field sizes are specified in bytes, not bits.
    """
    return (value_to_bytes(values.get(x,0),spec[x]) for x in spec.keys())

# Raster Dump classes

class RasterDump:
    """
    RasterDump is a basic raster canvas where the pixels are
    painted strictly top to bottom, left to right. Painting tools
    are restricted to individual pixels and horizontal lines.
    The RasterDump class is intended mainly for studying image
    compression codecs.

    This class supports 1-bit images. For 24-bit RGB support,
    use the RasterDumpRGB888 class.

    Please note that column padding is not automatically handled
    in the event the width of the image is not a multiple of 8px.
    See __init__() for more usage instructions.
    """
    bpp = 1
    MIN_HEIGHT = 1
    MIN_WIDTH = 8

    def __init__(self, w, h, pad=b'\x00'):
        """
        Create a Raster Dump

        w: width
        h: height
        pad: byte pattern for unmarked areas of the raster
            * example 1bpp pad pattern: b'\\x99'
            * example 24bpp pad pattern: b'\\xFF\\x00\\x00\\x00\\xFF\\x00\\x00\\x00\\xFF'
        """
        if type(pad) is not bytes:
                raise TypeError("pad must be a byte array (bytes)")
        self.width = w
        self.height = h
        self.raster = BytesIO()
        self.raster_size = self._raster_size() # in bytes
        self.pad = pad # pattern or colour for absent pixels

        if self.raster_size < 1:
            raise ValueError(
                'raster too small, min size: {}x{}'.format(
                    self.MIN_WIDTH, self.MIN_HEIGHT
                )
            )

    def _raster_position(self):
        return self.raster.tell()

    def _raster_size(self):
        # calc raster size in bytes
        return (ceil(self.width/8) * self.height)

    def clear(self):
        self.raster.truncate(0)

    def put_raster_bytes(self, b, count=1):
        if type(b) is not bytes:
            raise TypeError("b must be a byte array (bytes)")
        inp = b*count
        # clip off bytes that reach past end of raster
        c = min( len(inp), max(0,self.raster_size-self._raster_position()) )
        if c:
            self.raster.write(inp[:c])

    def get_raster(self):
        """
        Returns the entire contents of the raster in a
        blob/byte array (bytes)
        """
        self.raster.seek(0)
        pattern = cycle(self.pad)
        present = self.raster.read(self.raster_size)
        absent = (
            next(pattern)
            for x in range(max(self.raster_size-self._raster_position(),0))
        )
        return b''.join( (present, bytes(absent)) )

    def get_row_byte_size(self):
        """
        Returns the number of bytes to be allocated for one
        full horizontal line (row) of the raster
        """
        if self.bpp < 1:
            raise ValueError('rasters should have at least 1 bit/px')
        return ceil((self.width * self.bpp)/8)

class RasterDumpGray8(RasterDump):
    bpp = 8
    MIN_HEIGHT = 1
    MIN_WIDTH = 1

    def _raster_size(self):
        # calc raster size in bytes
        return self.width * self.height

    def put_pixels(self, v, count=1):
        # put grey pixels of level v into the raster
        # v can be between 0 (darkest) and 255 (lightest)
        if type(v) is not int:
            raise ValueError('v must be an int')
        if (v > 255) or (v < 0):
            raise ValueError('v must be 0 to 255')
        self.put_raster_bytes(bytes(v)*count)

class RasterDumpRGB888(RasterDump):
    """
    Raster Dump for 24-bit RGB full colour images.
    Pixel format is good old R8b+G8b+B8b.
    """
    bpp = 24
    MIN_HEIGHT = 1
    MIN_WIDTH = 1

    def _raster_size(self):
        # calc raster size in bytes
        return (self.width * self.height)*3

    def put_pixels(self, r, g, b, count=1):
        inp = bytes((r,g,b)*count)
        self.put_raster_bytes(inp)

class RasterDumpBGR888(RasterDumpRGB888):
    """
    Raster dump for 24-bit RGB full colour images
    specially for litte-endian data formats, which
    may flip the colour order to BGR.

    Pixel format is B8b+G8b+R8b.
    """
    def put_pixels(self, r, g, b, count=1):
        self.put_raster_bytes(bytes((b,g,r)*count))

# Raster dump writer classes

class RasterWriter:
    """
    File output support
    """

    def __init__(self, raster, out_path, overwrite=False):
        """
        Create a file writer for a RasterDump

        raster: RasterDump canvas object
        out_path: path to the file to save image to
        overwrite: if False, the RasterWriter will not be created
            if the file at out_path exists.

        """
        if not issubclass(type(raster), RasterDump):
            raise TypeError("must use RasterDump object for raster")
        if access(out_path, F_OK) and not overwrite:
            raise FileExistsError("not overwriting existing file")
        self.path = out_path
        self.raster = raster

    def get_blob(self):
        raise TypeError("please use a subclass of the RasterWriter")

    def get_raster_bpp(self):
        return self.raster.bpp

    def write_out(self):
        """
        Writes the contents of the raster (self.raster) to the file
        (self.path).
        """
        with(open(self.path, mode='bw')) as f:
            f.write(self.get_blob())

class BMPWriter(RasterWriter):
    """
    Microsoft Windows BMP (BITMAPINFOHEADER) file output support

    Instructions on creating a writer are in RasterWriter.__init__()
    """

    BITMAPINFOHEADER_SPEC = {
        # based on info from
        # https://en.wikipedia.org/wiki/BMP_file_format
        'magic': 2,
        'bmp_size': 4,
        'app': 4,
        'img_offset': 4,
        'header_size': 4,
        'width': 4,
        'height': 4,
        'color_planes': 2,
        'bpp': 2,
        'compression': 4,
        'img_size': 4, # for compressed images, size when unpacked
        'x_res': 4,
        'y_res': 4,
        'palette_colors': 4,
        'important_colors': 4,
    } # header fields and field sizes
    BMP_HEADER_SIZE = 14
    DIB_HEADER_SIZE = 40 # BITMAPINFOHEADER
    BMP_PAD = b'\x00'

    def __init__(
        self, raster, out_path, overwrite=False,
        g_hue=0.889, g_min_L=0.25, g_max_L=0.825
    ):
        super().__init__(raster,out_path,overwrite)
        self.gray_hue = g_hue
        self.gray_min_L = g_min_L
        self.gray_max_L = g_max_L


    def _bmp_header(self):
        # prepare combined BMP & DIB header
        off = self.BMP_HEADER_SIZE \
            + self.DIB_HEADER_SIZE \
            + self._bmp_palette_colors()*4 \
            + self._bmp_gap1_size()
        stats = {
            'magic': b'BM',
            'bmp_size': self._bmp_file_size(),
            'app': b'\x00\x00\x00\x00',
            'img_offset': off,
            'header_size': self.DIB_HEADER_SIZE,
            'width': self.raster.width,
            'height': -self.raster.height,
            'color_planes': 1,
            'bpp': self.raster.bpp,
            'compression': b'\x00\x00\x00\x00',
            'img_size': self._bmp_img_size(),
            'x_res': 2538, # ~72 DPI
            'y_res': 2538,
            'palette_colors': self._bmp_palette_colors(),
            'important_colors': 0
        }
        return b''.join(
            dict_to_struct(stats,self.BITMAPINFOHEADER_SPEC)
        )

    def _bmp_file_size(self):
        return self.BMP_HEADER_SIZE \
            + self.DIB_HEADER_SIZE \
            + self._bmp_palette_colors() * 4 \
            + self._bmp_gap1_size() \
            + self._bmp_img_size()

    def _bmp_img_size(self):
        rsz = self._bmp_row_pad_size() + self.raster.get_row_byte_size()
        return rsz * self.raster.height

    def _bmp_gap1_size(self):
        hs = self.BMP_HEADER_SIZE + self.DIB_HEADER_SIZE
        ps = self._bmp_palette_colors() * 4 # palette colours are 32bit
        start_offset = hs+ps
        return ceil(start_offset/4)*4 - start_offset

    def _bmp_palette_colors(self):
        if self.raster.bpp <= 8:
            return 2**self.raster.bpp
        else: return 0

    def _bmp_img_data(self):
        """
        Return raster data reformatted for the BMP format, with row
        padding to keep each raster row a multiple of 4 bytes.
        """
        s = self.raster.get_row_byte_size()
        p = self._bmp_row_pad_size()
        pbytes = self.BMP_PAD * p
        raster_iter = iter(self.raster.get_raster())
        out = b''
        for i in range(self.raster.height):
            row = b''.join((
                bytes(next(raster_iter) for x in range(s)),
                pbytes
            )) # NOTE: JS-style double bracket
            out = b''.join((out,row))
        return out

    def _bmp_row_pad_size(self):
        rbl = self.raster.get_row_byte_size()
        bmprbl = ceil(rbl/4)*4
        return bmprbl - rbl

    def _bmp_monochrome_palette(self):
        """
        Generate and return a BMP palette for a greyscale image,
        with the right number of shades to match the bits per
        pixel count of the raster.

        Supported bpp's are 1, 2, 4 and 8.

        max_lum: set the lightness of the lightest shade from
            0 to 1.0. A max_lum of 0 is black, while 1.0 is
            white and 0.5 is a vibrant colour.
        min_lum: set the lightness of the darkest shade from
            0 to 1.0. Behaves like max_lum.
        hue: set the colour of the shades, from 0 to 1.0.
            A hue of 0 is red, 1/3 is green and 2/3 is blue.
            The hue fades back to red via indigo and violet
            between 2/3 to 1.0; after 1.0 the hue wraps back to 0.
        """
        avail_bpp = (1,2,4,8)
        if(self.raster.bpp not in avail_bpp): return b''

        steps = 2**self.raster.bpp
        maxL = self.gray_max_L
        minL = self.gray_min_L
        get_lume = lambda x: (maxL-minL)/steps*x + minL
        Lumes = (get_lume(x) for x in range(1, 1+steps))
        colors = (hls_to_rgb(self.gray_hue, y, 1.0) for y in Lumes)
        bgras = ((ceil(255*b), ceil(255*g), ceil(255*r), 255) for r,g,b in colors)
        bs = (bytes(x) for x in bgras) # BGRA is ARGB litle-endian
        return b''.join(bs)

    def get_blob(self):
        """Prepare content for writing to file"""
        head = self._bmp_header()
        palette = self._bmp_monochrome_palette()
        gap1 = b'\x00' * self._bmp_gap1_size()
        img_data = self._bmp_img_data()
        return b''.join((head, palette, gap1, img_data))

class PBMWriter(RasterWriter):
    """
    Netpbm file output support

    Instructions on creating a writer are in RasterWriter.__init__()

    Note: PBMWriter does not support RasterDumpBGR888 rasters
    """
    HEADER_FORMAT = "{rtype}\n{w} {h}{maxval}" # HACK: maxval is \n for P4
    # lookups
    CLASS_TO_CONFIG = {
        RasterDump: ("P4", "\n"),
        RasterDumpGray8: ("P5", "\n255\n"),
        RasterDumpRGB888: ("P6", "\n255\n"),
    } # format: (magic, maxval)

    def get_blob(self):
        """Prepare content for writing to file"""
        cls = type(self.raster)
        clsbase = cls.__base__
        config = (
            self.CLASS_TO_CONFIG.get(cls)
            or self.CLASS_TO_CONFIG.get(clsbase)
        )
        header = self.HEADER_FORMAT.format(
            rtype = config[0],
            w = self.raster.width,
            h = self.raster.height,
            maxval = config[1]
        )
        return b''.join((bytes(header, 'ascii'), self.raster.get_raster()))

# Test Rasters and Writers
rastg8 = RasterDumpGray8(256,256)
bmpg8 = BMPWriter(rastg8, 'test-gray8.bmp', overwrite=True, g_hue=0.125)
pbmg8 = PBMWriter(rastg8, 'test-gray8.pbm', overwrite=True)

rastrgb = RasterDumpRGB888(17,17,pad=b'\xFF\x00\x00\x00\xFF\x00\x00\x00\xFF')
rastbgr = RasterDumpBGR888(17,17,pad=b'\x00\x00\xFF\x00\xFF\x00\xFF\x00\x00')
bmpbgr = BMPWriter(rastbgr, 'test-rgb.bmp', overwrite=True)
pbmrgb = PBMWriter(rastrgb, 'test-rgb.pbm', overwrite=True)

rast = RasterDump(128,128,pad=b'\xFF')
bmpwr = BMPWriter(rast, 'test.bmp', overwrite=True)
pbmwr = PBMWriter(rast, 'test.pbm', overwrite=True)
