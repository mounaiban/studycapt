#! /bin/python
"""
RLE Test Page Generator
Create rasters with funky patterns for studying run-length encoding
(RLE) techniques. Rasters are output in netpbm format (P4 for black-
and-white, P5 for greyscale and P6 for colour).

The original purpose of this module was to reverse-engineer the Smart
Compression Architecture (SCoA) format primarily used by early-2000s and
late-1990s Canon laser printers.

"""
# Written by Moses Chong
# First edition 2022/04/15
# Second edition 2022/05/01
# Third edition 2026/06/06
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

# NOTES
# =====
# * This script is currently fairly slow; a 600dpi A4-sized page takes
#   over a minute on a 2016-vintage low-end PC to create.
#
# * If no output file is specified as part of the --out_file= argmuent and
#   no redirection is used at the command line, the terminal will be flooded
#   with binary data.
#
from argparse import ArgumentParser
from collections import OrderedDict
from itertools import accumulate, chain
from math import ceil
from os.path import expanduser
from rasterdump import RasterDump, RasterDumpGray8, \
    RasterDumpRGB888, PBMWriter
from sys import argv, stdout

PX_VALUE_DEFAULT = 127
P4_MIN_VALUE = 127
P5_MAX_VALUE = 255
SQUARE_SIZE_DEFAULT = 64

# Plotting & Blotting Functions

# The functions in this section generate pixel data for the sample
# rasters.
#
# --------
# Creation
# --------
# For performance reasons, the functions are not hard-coded but
# prepared at runtime from an "_mk" creator function. These functions
# are run with the following conventions:
#
# _mk_fx(w, h, **kwargs)
#
# 'w' and 'h' are the width and height of the raster.
#
# Creator functions pre-calculate values that only need to be
# calculated once.
#
# ---------------------
# Usage and Conventions
# ---------------------
# These functions are run on every pixel in a raster, not unlike
# a shader. The argument format is as follows:
#
# fx(i, n)
#
# * 'i' is the pixel's position (ordinal) in the canvas;
#
#     * i == 0 for the upper left most pixel,
#
#     * i == width - 1 for the upper right most pixel,
#
#     * i == width + 1 for the left most pixel on the following line
#       and so on...
#
# * 'n' is the number of pixels to return following pixel i.
#
# Pixels are returned as an iter of integers, specifically a generator.
# Functions work within an 8 bit/colour limit. No CAPT printer is known
# to be capable of a deeper colour depth (e.g. 10-bit).
#
# Grey pixels are returned as an 8-bit value.
#
# Bi-level pixel output is derived from grey pixels; grey pixels
# with a value of 127 (0x7F) or higher are converted to a set pixel,
# while pixels of a lower value are left unset.
#
# Full-colour pixels are to packed in a 24-bit integer, identical in
# structure to a hex code: primary red is 0xFF0000, primary green is
# 0x00FF00 and primary blue is 0x0000FF.
#

def _mk_fn_all_clear(w, h, **kwargs):
    """Create a function that yields pixels for a blank page"""

    kwargs['value'] = 0x0
    return _mk_fn_all_set(w, h, **kwargs)

def _mk_fn_all_set(w, h, **kwargs):
    """
    Create a function that yields pixels for page entirely set to
    a shade of grey.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.

    """
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    img_w = w
    img_h = h
    n_px = h * w

    def _fn_all_set(i, n):
        return (v for x in range(min(n_px-i, n)))

    return _fn_all_set

def _mk_fn_checkerboard(w, h, **kwargs):
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    img_w = w
    img_h = h
    ssz = kwargs.get('square_size', SQUARE_SIZE_DEFAULT)
    gx = kwargs.get('grate_x', w+1)
    gy = kwargs.get('grate_y', h+1)
    mleft = kwargs.get('margin_left', 0)
    n_px = w * h
    # TODO: mleft currently only erases pixels on the left side of
    # the page. Maybe find a way to move the pattern to the right
    # without changing it?

    def _fn_checkerboard(i, n):
        for j in range(min(n_px-i, n)):
            i_px = i+j
            y = i_px // img_w
            x = i_px % img_w
            odd_row = (y // ssz) & 0x01
            odd_col = (x // ssz) & 0x01
            if ((odd_row and odd_col) or (not odd_row and not odd_col))\
               and (x%gx and y%gy)\
               and x > mleft: yield v
            else: yield 0x0

    return _fn_checkerboard

def _mk_fn_gradient_horizontal(w, h, **kwargs):
    """
    Creates a function to output a horizontal, linear, white-to-black
    greyscale gradient. Intended for use with P5 output only.

    Keyword arguments: 'value' (int) - value of the darkest shade,
    from 0x00 to 0xFF
    """
    img_w = w
    img_h = h
    n_px = h * w
    v = kwargs.get('value', P5_MAX_VALUE)

    def _fn_gradient_horizontal(i, n):
        for j in range(min(n_px-i, n)):
            y = (i+j) // img_w
            yield ceil(v * (y/img_h))

    return _fn_gradient_horizontal

def _mk_fn_incr_runs_2_pow_x(w, h, **kwargs):
    """
    Creates a function that plots runs of pixels that double in length
    further down the page. Each run is accompanied by a space of an
    equal number of pixels. Runs wrap around from right side of the to
    the left of the next line.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.
    """

    v = kwargs.get('value', PX_VALUE_DEFAULT)
    mt = kwargs.get('margin_top', 20)
    img_w = w
    img_h = h
    n_px = h * w

    def _fn_incr_runs_2_pow_x(i, n):
        for x in range(min(n_px-i, n)):
            i_px = i + x - (mt * img_w)
            b = 2**(i_px.bit_length()-1) # bias
            run_ord = i_px - b # pixel position in run
            if run_ord >= b//2: yield v
            else: yield 0x0

    return _fn_incr_runs_2_pow_x

def _mk_fn_incr_runs(w, h, **kwargs):
    img_w = w
    img_h = h
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    n_px = h * w

    def _fn_incr_runs(i, n):
        for x in range(min(n_px-i, n)):
            i_px = i + x
            y = i_px/img_w
            x = i_px%img_w
            if x%(y or 1) >= y//2: yield v
            else: yield 0x00

    return _fn_incr_runs

def _mk_fn_circle(w, h, **kwargs):
    """
    Create a function that yields pixels for a page with a single circle
    in the middle.
    """
    r_sq = (min(w,h)/2.5)**2 # radius is based off w or h, whichever is smaller
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    gx = kwargs.get('grate_x', w+1)
    gy = kwargs.get('grate_y', h+1)
    img_w = w
    img_h = h
    n_px = h * w
    half_img_w = w/2
    half_img_h = h/2
    n_px = h * w

    def _fn_circle(i, n):
        for j in range(min(n_px-i, n)):
            y = (i+j) // img_w
            x = (i+j) % img_w
            if (x-half_img_w)**2 + (y-half_img_h)**2 <= r_sq and x%gx and y%gy:
                yield v
            else: yield 0x00

    return _fn_circle

def _mk_fn_half_diagonal(w, h, **kwargs):
    """
    Shade the whole area on or below a diagonal line, which by default
    runs from the upper left to the lower right.

    Keyword Arguments
    -----------------
    m - the angle of the line

    c - the position of the line

    """
    img_w = w
    img_h = h
    m = kwargs.get('m', h/w)
    c = kwargs.get('c', 0)
    gx = kwargs.get('grate_x', w+1)
    gy = kwargs.get('grate_y', h+1)
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    mleft = kwargs.get('margin_left', 0)
    n_px = h * w

    def _fn_half_diagonal(i, n):
        for x in range(min(n_px-i, n)):
            i_px = i + x
            x = i_px % img_w
            y = i_px // img_w
            if x > mleft and y >= (m * (x-mleft)) + c and x%gx and y%gy:
                yield v
            # PROTIP: threshold line eq. is y == m * x + c
            else: yield 0x00

    return _fn_half_diagonal

def _mk_fn_reversed_half_diagonal(w, h, **kwargs):
    """
    Shade the whole area on or below a diagonal line running from the
    lower left to the upper right.
    """
    return _mk_fn_half_diagonal(w, h, m=-h/w, c=h, **kwargs)

def _mk_fn_half_horizontal(w, h, **kwargs):
    """
    Create a function that shades all pixels on or below halfway
    down the page.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.

    """
    img_w = w
    img_h = h
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    n_px = h * w

    def _fn_half_horizontal(i, n):
        for x in range(min(n_px-i, n)):
            i_px = i + x
            if i_px/img_w >= img_h//2: yield v
            else: yield 0x00

    return _fn_half_horizontal

def _mk_fn_mirrored_incr_runs(w, h, **kwargs):
    img_w = w
    img_h = h
    half_img_h = h//2
    v = kwargs.get('value', PX_VALUE_DEFAULT)
    n_px = h * w

    def _fn_mirrored_incr_runs(i, n):
        for x in range(min(n_px-i, n)):
            i_px = i + x
            x = i_px % img_w
            y = i_px // img_w
            k = y - half_img_h
            if x%(k or 1) >= k//2: yield v
            else: yield 0x00

    return _fn_mirrored_incr_runs

def _mk_fn_quarter_diagonal(w, h, **kwargs):
    """
    Create a function that shades all pixels on or below a diagonal
    line running from the upper left to midpoint between the upper
    and lower right.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.

    """
    return _mk_fn_half_diagonal(w, h, m=(h//2)/w, **kwargs)

def _mk_fn_primary_colors(w, h, **kwargs):
    """
    Create a function that constructs a patten such that there
    are stripes of RGB and CMY primary colours, punctuated by
    a black and a white stripe. The pattern cycles twice along
    the height of the raster.
    """

    img_w = w
    img_h = h
    n_px = h * w
    colors = (
        (255, 0 ,0),    # red
        (255, 255, 0),  # yellow
        (0, 255, 0),    # green
        (0, 255, 255),  # cyan
        (0, 0, 255),    # blue
        (255, 0, 255),  # magenta
        (0, 0, 0),      # black
        (255, 255, 255) # white
    )
    nc = len(colors)
    band_h = img_h // nc // 2

    def _fn_primary_colors(i, n):
        for j in range(min(n_px-i, n)):
            yield colors[(j+i)//img_w//band_h%nc]

    return _fn_primary_colors

# RasterPlot classes

class RasterPlot(RasterDump):
    """
    Raster dump for rendering plotting & blot functions to a
    1-bit bi-level image.

    RasterPlot uses RasterDump's pad pattern attribute and is
    therefore intended for use with an empty raster buffer.
    Please do not use the put_pixel_bytes() method with
    this class.
    """
    def __init__(self, w, h, fn):
        super().__init__(w, h)
        self.fn = fn
        self.threshold = 127
        self.pad = chain.from_iterable(
            (self._fill_row(i) for i in range(self.height))
        )

    def _fill_pre_byte(self, v, i, L):
        #  returns 2**(L-i) if v is equal to or over
        #  the threshold, and zero if it not.
        if v >= self.threshold: return 2**(L-i)
        else: return 0

    def _fill_byte(self, vs):
        """
        Condenses a run of eight 1-bit pixels into a single byte.

        This is done by first replacing all values in a tuple of
        ints that fall on or above a threshold (self.threshold)
        with a power-of-two value based on the value's position
        in the tuple, while zeroing out the values that fall
        below this threshold.

        The tuple is finally reduced into a single scalar value
        with bitwise OR of every value.

        Example, where the threshold is 127:
        (127, 0, 0, 1, 192, 168, 0, 1) => (128, 0, 0, 0, 8, 4, 0, 0)
        after reducing: 127 | 8 | 4 => 140

        in hex: \\x80\\x00\\x00\\x00\\x08\\x04\\x00\\x00 => \\x8C

        """
        p = (self._fill_pre_byte(vs[i], i, 7) for i in range(8))
        t = tuple(accumulate(p, lambda x,y:x|y))
        return t[-1]

    def _fill_row(self, i):
        # return the ith row of the sample blot function
        s = self.width * i  # row start pixel index
        n_pad = ceil(self.width/8)*8 - self.width
        n = self.width + n_pad
        pixs = self.fn(s, self.width)
        pad = (0x00,) * n_pad
        row = tuple(chain(pixs, pad))
        return tuple(
            (self._fill_byte(row[x:x+8])for x in range(0,n,8))
        )

class RasterPlotGray8(RasterDumpGray8):
    """
    Raster dump for rendering plotting & blot functions to an
    8-bit greyscale image.

    RasterPlot uses RasterDump's pad pattern attribute and is
    therefore intended for use with an empty raster buffer.
    Please do not use the put_pixel_bytes() or put_pixel()
    methods with this class.
    """
    MAX_VALUE = 255

    def __init__(self, w, h, fn):
        super().__init__(w, h)
        self.fn = fn
        self.threshold = 127
        self.pad = (
            self.MAX_VALUE-x for x in self.fn(0,self.width*self.height)
        )

class RasterPlotRGB888(RasterDumpRGB888):
    """
    Raster dump for rendering plotting & blot functions to an
    8-bit greyscale image.

    RasterPlot uses RasterDump's pad pattern attribute and is
    therefore intended for use with an empty raster buffer.
    Please do not use the put_pixel_bytes() or put_pixel()
    methods with this class.
    """
    def __init__(self, w, h, fn):
        super().__init__(w, h)
        self.fn = fn
        self.threshold = 127
        self.pad = chain.from_iterable(
            x for x in self.fn(0,self.width*self.height)
        )

# Shell Command Line Handler

SIZES_600D = OrderedDict({
    'a4': (4958, 7016),
    'a5': (3500, 4958),
    'f4': (5100, 7800), # aka 'flsa'
    'jis-b5': (4300, 6075),
    'index-3x5': (1800, 3000),
    'legal': (5100, 8400),
    'letter': (5100, 6600),
    'sac-16k': (4608, 6375), # simply '16k' in Canon PPDs
})# Sizes are in pixels at 600dpi. Figures taken from GhostScript 9.26,
  # from /usr/share/ghostscript/9.26/Resource/Init/gs_statd.ps
  #
  # Pixel sizes calculated from PostScript points in bc with scale=15
  # (1/72) * point_size * 600, then rounded to an integer.
  #
  # Size for 16K and 3x5in Index Cards taken from Canon PPDs
  # (CNCUPSLBP1120CAPTK.ppd)
PATTERNS_FNS = OrderedDict({
    'all-clear': {
        'fn': _mk_fn_all_clear,
        'raster_class': RasterPlot
    },
    'all-set': {
        'fn': _mk_fn_all_set,
        'raster_class': RasterPlot
    },
    'all-set-gray': {
        'fn': _mk_fn_all_set,
        'raster_class': RasterPlotGray8
    },
    'checkerboard': {
        'fn': _mk_fn_checkerboard,
        'raster_class': RasterPlot
    },
    'circle': {
        'fn': _mk_fn_circle,
        'raster_class': RasterPlot
    },
    'gradient-horizontal': {
        'fn': _mk_fn_gradient_horizontal,
        'raster_class': RasterPlotGray8
    },
    'half-diagonal': {
        'fn': _mk_fn_half_diagonal,
        'raster_class': RasterPlot
    },
    'reversed-half-diagonal': {
        'fn': _mk_fn_reversed_half_diagonal,
        'raster_class': RasterPlot
    },
    'half-horizontal': {
        'fn': _mk_fn_half_horizontal,
        'raster_class': RasterPlot
    },
    'mirrored-incr-runs': {
        'fn': _mk_fn_mirrored_incr_runs,
        'raster_class': RasterPlot
    },
    'incr-runs': {
        'fn': _mk_fn_incr_runs,
        'raster_class': RasterPlot
    },
    'incr-runs-2-pow-x': {
        'fn': _mk_fn_incr_runs_2_pow_x,
        'raster_class': RasterPlot
    },
    'quarter-diagonal': {
        'fn': _mk_fn_quarter_diagonal,
        'raster_class': RasterPlot
    },
    'primary-colors': {
        'fn': _mk_fn_primary_colors,
        'raster_class': RasterPlotRGB888
    }
})
RASTER_CLASS_TO_DESC = {
    RasterPlot: 'Black & White/P4',
    RasterPlotGray8: 'Greyscale 8-bit/P5',
    RasterPlotRGB888: 'Colour 24-bit/P6'
}

RESOLUTIONS_F = OrderedDict({
    '600': 1.0,
    '300': 0.5,
    '150': 0.25,
    '75': 0.125,
    '37.5': 0.0625,
    '18.75': 0.03125,
}) # PROTIP: Choices must be strings.
# Lower resolutions are only intended for illustrative purposes

def print_mode_details():
    spaces = lambda x: max(28-x, 1)
    spair = lambda x,y: "{}{}{}".format(x, ' '*spaces(len(x)), y)
    print('--mode option missing')
    print('please select a pattern mode from below:\n')
    print('\x1b[1m\x1b[38:5:204m',end='')
    print(spair('mode', 'output format'))
    print('\x1b[0m', end='')
    for x in PATTERNS_FNS.keys():
        rast_class = PATTERNS_FNS[x]['raster_class']
        print(spair(x, RASTER_CLASS_TO_DESC[rast_class]))

if __name__ == '__main__':
    with_g = 'checkerboard', 'circle', 'half-diagonal'
        # modes where grate control is available
    with_mleft = 'checkerboard', 'half-diagonal'
        # modes where left margin control is available
    with_value = tuple(
        x for x in PATTERNS_FNS.keys() \
        if PATTERNS_FNS[x]['raster_class'] is RasterPlotGray8
    )   # modes that output greyscale images
    parser_spec = OrderedDict({
        'desc': 'Generate PBM for RLE compression studies',
        'help': 'hi',
        'args': {
            '--size': {
                'choices': SIZES_600D.keys(),
                'required': True,
                'help': 'test page size',
            },
            '--resolution': {
                'choices': RESOLUTIONS_F.keys(),
                'default': next(iter(RESOLUTIONS_F.keys())),
                'help': 'sample page resolution in DPI'
            },
            '--format': {
                'deprecated': True,
                'help': 'deprecated, now selected automatically'
            },
            '--grate_x': {
                'default': None,
                'help': "clear pixel every x'th column ({} only)".format(with_g)
            },
            '--grate_y': {
                'default': None,
                'help': "clear pixel every y'th row ({} only)".format(with_g)
            },
            '--square_size': {
                'default': SQUARE_SIZE_DEFAULT,
                'help': "size of checkered squares (checkerboard mode only)"
            },
            '--margin_left': {
                'default': 0,
                'help': "left margin in pixels ({} only)".format(with_mleft),
            },
            '--mode': {
                'choices': PATTERNS_FNS.keys(),
                'help': 'test pattern type, see module for details'
            },
            '--out_file': {
                'default': None,
                'help': 'path to output file; omit to use standard output'
            },
            '--value': {
                'default': '127',
                'help': "grey value to use for greyscale modes (0-255) ({} only)".format(with_value)
            },
            '--p5_value': {
                'deprecated': True,
                'default': '127',
                'help': 'deprecated, please use --value'
            },        }
    })
    parser = ArgumentParser(description=parser_spec['desc'])
    for k_arg in parser_spec['args']:
        spec_arg = parser_spec['args'][k_arg]
        parser.add_argument(
            k_arg,
            default=spec_arg.get('default'),
            choices=spec_arg.get('choices'),
            required=spec_arg.get('required', False),
            help=spec_arg.get('help'),
            deprecated=spec_arg.get('deprecated', False)
        )
    args = parser.parse_args()
    if not args.mode:
        print_mode_details()
        exit()
    size = SIZES_600D[args.size]
    fact = RESOLUTIONS_F[args.resolution]
    w = int(round(size[0] * fact))
    h = int(round(size[1] * fact))
    gx = int(args.grate_x or w+1)
    gy = int(args.grate_y or h+1)
    mleft = int(args.margin_left)
    mkfn_px = PATTERNS_FNS[args.mode]['fn']
    val = int(args.value or args.p5_value)
    csz = int(args.square_size)
    fn_px = mkfn_px(
        w,
        h,
        value=val,
        grate_x=gx,
        grate_y=gy,
        margin_left=mleft,
        square_size=csz,
    )
    cls_rast = PATTERNS_FNS[args.mode]['raster_class']
    rast = cls_rast(w, h, fn_px)
    if args.out_file:
        writer = PBMWriter(rast, expanduser(args.out_file)).write_out()
    else:
        writer = PBMWriter(rast, "", overwrite=False)
        stdout.buffer.write(writer.get_blob())
