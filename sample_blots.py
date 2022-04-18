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
# * All output is routed to stdout. In other words, if you run this script
#   from a terminal window without redirecting output to a file, the terminal
#   window will be flooded with binary data.
#

from argparse import ArgumentParser
from math import ceil
from os.path import expanduser
from sys import argv, stdout

TITLE = "Studycapt Checkerboard Sample"
PIXELS_PER_BYTE = 8

# Plotting & Blotting Functions

# Please see sample_page() below for function specifications
#
# TODO: Should these return closures instead? Closures could potentially
#  be faster by allowing us to skip kwargs lookups.

def _fn_one_dot(w, h, x, y, **kwargs):
    """Plot a single dot on the canvas. Intended for debugging."""
    dot_x = kwargs.get('dot_x', 0)
    dot_y = kwargs.get('dot_y', 0)
    return x == dot_x and y == dot_y

def _fn_incr_runs_2_pow_x(w, h, x, y, **kwargs):
    """
    Plots runs of pixels that double in size further down the page.
    Each runs trial behind a space of an equal number of pixels.
    """
    i_px = y*w + x
    b = 2**(i_px.bit_length()-1) # bias
    run_ord = i_px - b
    return run_ord >= b//2

def _fn_incr_runs(w, h, x, y, **kwargs):
    """
    Plots runs of pixels seprated by equally-sized spaces. Runs increase
    gradually further down the page. Every other row has pixel runs that are
    exactly one pixel longer than spaces on the same line.
    """
    return x%(y or 1) >= y//2

def _fn_circle(w, h, x, y, **kwargs):
    """Plot a circle in the middle of the canvas"""
    return (x-w/2)**2 + (y-h/2)**2 <= (min(w,h)/2.5)**2

def _fn_half_triangle(w, h, x, y, **kwargs):
    """
    Shade all pixels on the canvas on or below a diagonal line running from
    the upper left to the lower right.
    """
    return y >= (min(w,h)/max(w,h))*x

# Raster setup functions

def _p4_set_pixel(bytemap, w, x, y, set_bit=True):
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
    if (x*y)/8 > len(bytemap): raise IndexError('bit_pos past last bit')
    bytes_per_row = ceil(w/8)
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
    Create a sample page. Pages created by this function are output as
    PBM raster images.

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
    config = "# {}; params: {}".format(TITLE, kwargs)
    out = bytes("P4\n{}\n{} {}\x0a".format(config, w, h), encoding='ascii')
    pixels = _p4_new_raster(w, h)
    for i in range(h):
        for j in range(w):
            _p4_set_pixel(pixels, w, j, i, fn(w, h, j, i, **kwargs))
    return out.join((b'', bytes(pixels)))

# Shell Command Line Handler

IN_PER_MM = 1/25.4 # inch to mm conversion
SIZES = {
    'a4': (210, 297),
    'a5': (148, 210),
    'f4': (215.9, 330),
    'jis-b5': (182, 257),
    'legal': (215.9, 355.6),
    'letter': (215.9, 27.94),
    'sac-16k': (195, 270),
} # sizes are in mm only
MODES_FNS = {
    'circle': _fn_circle,
    'triangle': _fn_half_triangle,
    'incr_runs': _fn_incr_runs,
    'incr_runs_2_pow_x': _fn_incr_runs_2_pow_x,
}
RESOLUTIONS_DPI = ('600', '300', '150') # TODO: must choices be strings?

if __name__ == '__main__':
    parser_spec = {
        'desc': 'Generate PBM P4 for RLE compression studies',
        'help': 'hi',
        'args': {
            '--size': {
                'choices': SIZES.keys(),
                'required': True,
                'help': 'test page size',
            },
            '--resolution': {
                'choices': RESOLUTIONS_DPI,
                'default': RESOLUTIONS_DPI[0],
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
    px_per_mm = int(args.resolution) * IN_PER_MM
    size = SIZES[args.size]
    w = int(round(size[0], 2) * px_per_mm)
    h = int(round(size[1], 2) * px_per_mm)
    _do_out = lambda: sample_page(w, h, fn=MODES_FNS[args.mode])
    if args.out_file:
        with open(expanduser(args.out_file), mode='bx') as f:
            f.write(_do_out())
            f.close()
    else:
        stdout.buffer.write(_do_out())

