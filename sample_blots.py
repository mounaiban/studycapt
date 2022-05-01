#! /bin/python
"""
RLE Test Page Generator
Create a single P4 PBM raster with funky patterns for studying run-length
encoding (RLE) techniques.

The original purpose of this module was to reverse-engineer the Smart 
Compression Architecture (SCoA) format primarily used by early-2000s and late-
1990s Canon laser printers.

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

# NOTES
# =====
# * This script is currently very slow; generating a 600dpi A4-sized page takes
#   several minutes on a 2016-vintage, low-end PC.
#
# * If no output file is specified as part of the --out_file= argmuent and
#   no redirection is used at the command line, the terminal will be flooded
#   with binary data.
#
from argparse import ArgumentParser
from collections import OrderedDict
from itertools import chain
from math import ceil
from os.path import expanduser
from sys import argv, stdout

TITLE = "Studycapt RLE Study"
PIXELS_PER_BYTE = 8
HEADER_FMT = "{}\n# Studycapt RLE Study\n# {}\n{} {}\n"

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
# Grey pixels are returned as an 8-bit value; bi-level pixels are set
# when a value of 127 (0x7F) or higher is returned.
#
# Full-colour pixels are to packed in a 24-bit integer, identical in
# structure to a hex code: primary red is 0xFF0000, primary green is
# 0x00FF00 and primary blue is 0x0000FF.
#

def _fn_all_clear(w, h, x, y, **kwargs):
    """Clear all pixels"""
    return False

def _mk_fn_all_clear(w, h, **kwargs):
    """Create a function that yields pixels for a blank page"""

    def _fn_all_clear(i, n):
        img_w = w
        img_h = h
        if i + n > img_w * img_h: raise ValueError("index i out of bounds")
        # Simplification of i + n - 1 > img_w * img_h
        return (0x00 for x in range(n))

    return _fn_all_clear

def _fn_all_set(w, h, x, y, **kwargs):
    """Set all pixels"""
    return True

def _mk_fn_all_set(w, h, **kwargs):
    """
    Create a function that yields pixels for page entirely set to
    a shade of grey.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.

    """
    v = kwargs.get('value', 0xFF)

    def _fn_all_set(i, n):
        img_w = w
        img_h = h
        if i + n > img_w * img_h: raise ValueError("index i out of bounds")
        return (v for x in range(n))

    return _fn_all_set

def _fn_one_dot(w, h, x, y, **kwargs):
    """Plot a single dot on the canvas. Intended for debugging."""
    dot_x = kwargs.get('dot_x', 0)
    dot_y = kwargs.get('dot_y', 0)
    return x == dot_x and y == dot_y

def _fn_incr_runs_2_pow_x(w, h, x, y, **kwargs):
    """
    Plots runs of pixels that double in size further down the page.
    Each run follows a space of an equal number of pixels. Runs and
    spaces that reach the right side of the page continue on the
    next line from the left.

    """
    i_px = y*w + x
    b = 2**(i_px.bit_length()-1) # bias
    run_ord = i_px - b
    return run_ord >= b//2

def _mk_fn_incr_runs_2_pow_x(w, h, **kwargs):
    """
    Creates a function that plots runs of pixels that double in length
    further down the page. Each run is accompanied by a space of an
    equal number of pixels. Runs wrap around from right side of the to
    the left of the next line.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.
    """

    v = kwargs.get('value', 0xFF)
    mt = kwargs.get('margin_top', 20)
    img_w = w
    img_h = h

    def _fn_incr_runs_2_pow_x(i, n):
        if i + n > img_w * img_h: raise ValueError("index i out of bounds")
        for x in range(n):
            i_px = i + x - (mt * img_w)
            b = 2**(i_px.bit_length()-1) # bias
            run_ord = i_px - b # pixel position in run
            if run_ord >= b//2: yield v
            else: yield 0x0

    return _fn_incr_runs_2_pow_x

def _mk_fn_incr_runs(w, h, **kwargs):
    img_w = w
    img_h = h
    v = kwargs.get('value', 0xFF)

    def _fn_incr_runs(i, n):
        if i + n > img_w * img_h: raise ValueError("index i out of bounds")

        for x in range(n):
            i_px = i + x
            y = i_px/img_w
            x = i_px%img_w
            if x%(y or 1) >= y//2: yield v
            else: yield 0x00

    return _fn_incr_runs

def _fn_incr_runs(w, h, x, y, **kwargs):
    """
    Plots runs of pixels seprated by equally-sized spaces. Runs increase
    gradually further down the page. Runs end at the right side of the
    page.

    Every other row has pixel runs that are exactly one pixel longer
    than spaces on the same line.

    """
    return x%(y or 1) >= y//2

def _fn_circle(w, h, x, y, **kwargs):
    """Plot a circle in the middle of the page"""
    return (x-w/2)**2 + (y-h/2)**2 <= (min(w,h)/2.5)**2

def _mk_fn_circle(w, h, **kwargs):
    """
    Create a function that yields pixels for a page with a single circle
    in the middle.
    """
    d_short = min(w,h)

    def _fn_circle(i, n):
        img_w = w
        img_h = h
        if n >= img_w * img_h: raise ValueError("index i out of bounds")
        for j in range(n):
            y = (i+j) // w
            x = (i+j) % w
            if (x-w/2)**2 + (y-h/2)**2 <= (d_short/2.5)**2: yield 0xFF
            else: yield 0x00

    return _fn_circle

def _fn_half_diagonal(w, h, x, y, **kwargs):
    """
    Shade all pixels on or below the diagonal line running from the upper left
    to the lower right of the page.
    """
    return y >= (h/w)*x

def _mk_fn_half_diagonal(w, h, **kwargs):

    img_w = w
    img_h = h
    v = kwargs.get('value', 0xFF)

    def _fn_half_diagonal(i, n):
        if n >= img_w * img_h: raise ValueError("index i out of bounds")
        for x in range(n):
            i_px = i + x
            if i_px/img_w >= (img_h/img_w) * (i_px % img_w): yield v
            # PROTIP: threshold line eq. is y == m * x; m == img_h/img_w
            else: yield 0x00

    return _fn_half_diagonal

def _fn_half_horizontal(w, h, x, y, **kwargs):
    """Shade all pixels on or below halfway down the page."""
    return y >= h//2

def _mk_fn_half_horizontal(w, h, **kwargs):
    """
    Create a function that shades all pixels on or below halfway
    down the page.

    Keyword arguments: 'value' (int) - value of the pixel, 0x00 for
    white, 0xFF for black.

    """
    img_w = w
    img_h = h
    v = kwargs.get('value', 0xFF)

    def _fn_half_horizontal(i, n):
        if n >= img_w * img_h: raise ValueError("index i out of bounds")
        for x in range(n):
            i_px = i + x
            if i_px/img_w >= img_h//2: yield v
            else: yield 0x00

    return _fn_half_horizontal

def _fn_mirrored_incr_runs(w, h, x, y, **kwargs):
    """
    Same as _fn_incr_runs(), but the pattern is mirrored on an axis halfway
    down the page.

    """
    # NOTE: This function was actually an incorrect version of another
    # function intended to be a variation _fn_incr_runs() that starts
    # halfway down the page. It has been adopted beacuse it looks great.
    #
    k = y-(h//2)
    return x%(k or 1) >= k//2

def _mk_fn_mirrored_incr_runs(w, h, **kwargs):
    img_w = w
    img_h = h
    v = kwargs.get('value', 0xFF)

    def _fn_mirrored_incr_runs(i, n):
        if n >= img_w * img_h: raise ValueError("index i out of bounds")
        for x in range(n):
            i_px = i + x
            x = i_px % img_w
            y = i_px // img_w
            k = y - (h//2)
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
    img_w = w
    img_h = h
    v = kwargs.get('value', 0xFF)

    def _fn_quarter_diagonal(i, n):
        if n >= img_w * img_h: raise ValueError("index i out of bounds")
        for x in range(n):
            i_px = i + x
            if (i_px/img_w) >= ((img_h//2)/img_w)*(i_px%img_w): yield v
            else: yield 0x00

    return _fn_quarter_diagonal

def _fn_quarter_diagonal(w, h, x, y, **kwargs):
    """
    Shade all pixels on or below the diagonal line running from the upper left
    to the midpoint between the top right and to bottom right of the page.
    """
    return y >= ((h/2)/w)*x

# Raster setup functions

def _get_p5_raster(w, h, fn, comment=''):
    """
    Generate PGM P5 raster w pixels wide, h pixels tall, using pixel
    function fn. Return raster as an iter.

    """
    LMAX = 255
    header = bytes(
        HEADER_FMT.format('P5', comment, w, h, LMAX), encoding='ascii'
    )
    body = bytes(LMAX-x for x in fn(0, (w*h)-1))
    raster = chain(header, body)
    return (x for x in raster)

def _get_p4_raster(w, h, fn, comment=''):
    """
    Generate PBM P4 raster w pixels wide, h pixels tall, using pixel
    function fn. Return the reaster as an iter.

    Any pixel of value 127 and above will be set.

    """
    TMIN = 127
    header = bytes(
        HEADER_FMT.format('P4', comment, w, h), encoding='ascii'
    )
    rows = (_p4_get_row(w, fn(x, w), TMIN) for x in range(0,w*h, w))
    body = chain.from_iterable(r for r in rows)
    raster = chain(header, body)
    return (x for x in raster)

def _p4_get_row(w, v, t):
    """
    Format a row of pixel values 'v' for a P4 raster 'w' pixels wide.
    Any pixel of value 't' and above will be set.

    Pixels are returned as a row of packed ints (8-bit int where each
    bit represents one pixel).

    """
    out = [0x0,] * ceil(w/8)
    i = 0
    for val in v:
        if i >= w: return out
        byte_pos = i//8
        mask = 0x80 >> i%8
        if val >= t: out[byte_pos] |= mask
        i += 1
    return out

def _p4_set_pixel(bytemap, bytes_per_row, w, x, y, set_bit=True):
    """
    Sets a single pixel in a list or array representing a P4 bitmap.

    Arguments
    =========

    * bytemap: PBM P4 bitmap as a byte array

    * w: width of the bitmap (important for correct placement)

    * x, y: coordinates of the pixel; use video buffer coordinates (upper
      left is (0,0).

    * set_bit: set the pixel at (x,y) if True, clear it if False.
    """
    if (x >= w): raise IndexError('x out of bounds')
    col_byte_pos = y * bytes_per_row + x//PIXELS_PER_BYTE
    mask = 0x80 >> (x % 8)
    if set_bit:
        bytemap[col_byte_pos] |= mask
    if not set_bit:
        mask ^= 0xFF
        bytemap[col_byte_pos] &= mask

def _p4_new_raster(w, h, **kwargs):
    return [0x0,] * (ceil(w/8)*h)

def sample_page(w, h, fn, **kwargs):
    """
    Create a sample page. Pages are in PBM P4 format.

    Arguments
    =========
    
    * w, h: width and height of the page

    * fn: function to create pattern

    Function Specs
    ==============

    The function fn is run once for every pixel in the bitmap. The argument
    format is as follows: fn(w, h, x, y, **kwargs). 

    * w, h: width and height of the bitmap

    * x, y: coordinates of the pixel on the bitmap

    * kwargs: additional keyword arguments; all kwargs in this function are
      passed to fn

    If the function returns True given the values of the arguments, the pixel
    is marked. Returning False clears the pixel.

    """
    comment = kwargs.get('comment', '')
    desc = "# {} # {} #".format(TITLE, kwargs.get('comment', ''))
    out = bytes("P4\n{}\n{} {}\x0a".format(desc, w, h), encoding='ascii')
    pixels = _p4_new_raster(w, h)
    bytes_per_row = ceil(w/8)
    for i in range(h):
        for j in range(w):
            _p4_set_pixel(
                pixels, bytes_per_row, w, j, i, fn(w, h, j, i, **kwargs)
            )
    return out.join((b'', bytes(pixels)))

# Shell Command Line Handler

SIZES_600D = OrderedDict({
    'a4': (4958, 7016),
    'a5': (3500, 4958),
    'f4': (5100, 7800), # aka 'flsa'
    'jis-b5': (4300, 6075),
    'index-3x5': (1800, 3000),
    'legal': (5100, 8400),
    'letter': (1799, 6600),
    'sac-16k': (4608, 6375), # simply '16k' in Canon PPDs
})# Sizes are in pixels at 600dpi. Figures taken from GhostScript 9.26,
  # from /usr/share/ghostscript/9.26/Resource/Init/gs_statd.ps
  #
  # Pixel sizes calculated from PostScript points in bc with scale=15
  # (1/72) * point_size * 600, then rounded to an integer.
  #
  # Size for 16K and 3x5in Index Cards taken from Canon PPDs
  # (CNCUPSLBP1120CAPTK.ppd)
MODES_FNS = OrderedDict({
    'all-clear': _mk_fn_all_clear,
    'all-set': _mk_fn_all_set,
    'circle': _mk_fn_circle,
    'half-diagonal': _mk_fn_half_diagonal,
    'half-horizontal': _mk_fn_half_horizontal,
    'mirrored-incr-runs': _mk_fn_mirrored_incr_runs,
    'incr-runs': _mk_fn_incr_runs,
    'incr-runs-2-pow-x': _mk_fn_incr_runs_2_pow_x,
    'quarter-diagonal': _mk_fn_quarter_diagonal,
})
RESOLUTIONS_F = OrderedDict({
    '600': 1.0, '300': 0.5, '150': 0.25, '75': 0.125, '37.5': 0.0625
}) # PROTIP: Choices must be strings.
# Lower resolutions are only intended for illustrative purposes

if __name__ == '__main__':
    parser_spec = {
        'desc': 'Generate PBM P4 for RLE compression studies',
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
            '--mode': {
                'choices': MODES_FNS.keys(),
                'default': next(iter(MODES_FNS.keys())),
                'help': 'test pattern type, see module for details'
            },
            '--out_file': {
                'default': None,
                'help': 'path to output file; omit to use standard output'
            },
            '--comment': {
                'default': '',
                'help': 'one-liner comment to embed in output'
            }
        }
    }
    parser = ArgumentParser(description=parser_spec['desc'])
    for k_arg in parser_spec['args']:
        spec_arg = parser_spec['args'][k_arg]
        parser.add_argument(
            k_arg,
            default=spec_arg.get('default'),
            choices=spec_arg.get('choices'),
            required=spec_arg.get('required', False),
            help=spec_arg.get('help'),
        )
    args = parser.parse_args()
    size = SIZES_600D[args.size]
    fact = RESOLUTIONS_F[args.resolution]
    w = int(round(size[0] * fact))
    h = int(round(size[1] * fact))
    mkfn = MODES_FNS[args.mode]
    fn = mkfn(w, h)
    if True in map(lambda x: x in args.comment, '\x0a\n'):
        raise ValueError('newlines not permitted in comment')
    _do_out = lambda: bytes(_get_p4_raster(w, h, fn, args.comment))
    if args.out_file:
        with open(expanduser(args.out_file), mode='bx') as f:
            f.write(_do_out())
            f.close()
    else:
        stdout.buffer.write(_do_out())

