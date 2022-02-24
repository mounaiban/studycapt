#! /bin/python
"""
Print Test Page Generator: Balls
Create a single-page SVG test print document filled with ellipse balls.

The functions in this module are intended for generating test pages to verify
correctness of compression routines and to diagnose performance issues.

CUPS test pages are currently recommended instead for verifying accuracy of
output.

This module was created for use with Captdriver, but it should be suitable for
testing any other printer driver.

"""
# Written by Moses Chong
# (First public version: 2021/01/02)
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
#
# TODO: Can CSS further reduce output data size?
# TODO: Document argument format for functions
# TODO: Re-implement using XML API (xml.etree)

from argparse import ArgumentParser
from math import log2
from sys import argv, stderr

DOCTYPE = "<?xml version='1.0' encoding='UTF-8' standalone='no' ?>"
GREY = '#999'
SIZES = {
    'a4': (210, 297, 'mm'),
    'a5': (148, 210, 'mm'),
    'f4': (215.9, 330, 'mm'),
    'jis-b5': (182, 257, 'mm'),
    'legal': (8.5, 14, 'in'),
    'letter': (8.5, 11, 'in'),
    'sac-16k': (195, 270, 'mm'),
}
# MODES_FNS: see bottom of module, after function declarations
XMLNS_SVG = 'http://www.w3.org/2000/svg' 
XMLNS_XLINK = 'http://www.w3.org/1999/xlink'
UNIT_DEFAULT = 'mm'

svg_fmt = "<svg width='{}' height='{}' xmlns='{}' xmlns:xlink='{}'>\n" + \
    "{}</svg>"
defs_fmt = "<defs>\n{}</defs>\n"
desc_text_fmt = "An orderly arrangement of {n} by {n} {shading} balls"
desc_fmt = "<desc>{}</desc>\n"
grad_a = ((0, "000"),(100, "fff"))
grad_b = ((0, "eee"),(100, "000"))
grad_rb_a = (
    (0, "f0f"),
    (45, "00f"),
    (50, "0ff"),
    (60, "0f0"),
    (80, "ff0"),
    (100, "f00"),
)
grad_rb_b = (
    (grad_rb_a[x][0], grad_rb_a[-(x+1)][1]) for x in range(len(grad_rb_a))
) # take rb_a, keep the stops, reverse the order of the colours

q = lambda s, unit: "{}{}".format(s,unit) # quantity with unit as string
svg_s = lambda w,h,cont: svg_fmt.format(w, h, XMLNS_SVG, XMLNS_XLINK, cont)
    # build SVG section

def _ball_symbol(rw, r_h, unit=UNIT_DEFAULT):
    """
    Return a string containing the Ball SVG symbol.
    'Ball' (as in rugby ball) is an ellipse centered within an imaginary
    rectangle of size rw x rh.

    """
    BALL_ID = 'ball'
    qx_c = q(rw/2, unit)
    qy_c = q(r_h/2, unit)
    qrx = q(rw/2.03125, unit)
    qry = q(r_h/2.03125, unit)
    ellipse = "<ellipse cx='{}' cy='{}' rx='{}' ry='{}' />".format(
        qx_c, qy_c, qrx, qry
    )
    symbol = "<symbol id='{}'>\n{}\n</symbol>".format(BALL_ID, ellipse)
    return symbol

def _rad_gradient_def(stop_list, rg_id=0):
    """
    Return a string containing an SVG radial gradient definition.
    The gradient will have an id of rg-n where n == rg_id

    Format for stop_list: [[stop_1, color_1], ... [stop_n, color_n]];
    stop is an int/float percentage, color is an RGB hex string

    """
    rg_fmt = "<radialGradient id='rg-{}'>{}</radialGradient>"
    stop_fmt = "<stop offset='{}%' stop-color='#{}' />"
    stop_cnt = ''
    for s in stop_list:
        stop_cnt = ''.join((stop_cnt, stop_fmt.format(s[0], s[1]),))
    return rg_fmt.format(rg_id, stop_cnt)

def _ball(x, y, fill, unit=UNIT_DEFAULT, u_id=None):
    """
    Return a string containing an SVG reference to 'Ball', defined by
    _ball_symbol() above.

    * x, y: specify position of the Ball on the test page

    * fill: SVG colour/pattern/gradient paint server reference
      (see Scalable Vector Graphics Recommendation, Section 13)
      <https://www.w3.org/TR/SVG11/pservers.html> 

    * unit: specify SVG measurement unit

    * u_id: sets the XML id of the Ball

    """
    idp = ''
    if u_id is not None:
        idp = ''.join(("id='{0}'".format(u_id), ' ',))
    qx_r = q(x, unit)
    qy_r = q(y, unit)
    use = "<use {}x='{}' y='{}' fill='{}' xlink:href='#ball'/>".format(
        idp, qx_r, qy_r, fill
    )
    return use

def _black_flat_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a black ball on the test page.

    NOTE: argument i is not used; it is for compatibility purposes only.

    Arguments for x, y, unit and u_id have the same use as in _ball(), see
    _ball() above for usage.

    """
    return _ball(x, y, '#000', unit=unit, u_id=u_id)

def _grey_flat_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a grey ball on the test page.

    NOTE: argument i is not used; it is for compatibility purposes only.

    Arguments for x, y, unit and u_id have the same use as in _ball(), see
    _ball() above for usage.

    """
    return _ball(x, y, '#bbb', unit=unit, u_id=u_id)

def _color_flat_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a coloured ball on the test page.

    Argument i sets the fill of the ball:

    0: aqua-cyan, 1: magenta, 2: yellow, 3: black, 4: red, 5: green, 6: blue,
    7 onwards: repeat the cycle from 0 to 6; i = n % 7

    Arguments for x, y, unit and u_id have the same use as in _ball(), see
    _ball() above for usage.

    """
    fills = ('#0ff', '#f0f', '#ff0', '#000', '#f00', '#0f0', '#00f') # CMYKRGB
    k = i % len(fills)
    return _ball(x, y, fills[k], unit=unit, u_id=u_id)

def _gradi_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a grey radial gradient-filled ball on the
    test page.

    Argument i sets the fill of the ball:

    * zero and even numbers: black on the inside of the ball

    * odd numbers: black on the outside of the ball

    Arguments for x, y, unit and u_id have the same use as in _ball(), see
    _ball() above for usage.

    """
    k = i % 2
    fill_url = "url(#rg-{})".format(k)
    return _ball(x, y, fill_url, unit=unit, u_id=u_id)

def _rainbow_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a rainbow radial gradient-filled ball on the
    test page.

    Argument i sets the fill of the ball:

    * zero and even numbers: red on the outside to violet on the inside

    * odd numbers: violet on the outside to red on the inside

    Arguments for x, y, unit and u_id have the same use as in _ball(), see
    _ball() above for usage.

    """
    k = i % 2
    fill_url = "url(#rg-{})".format(k)
    return _ball(x, y, fill_url, unit=unit, u_id=u_id)

def balls_page(m, w, h, unit=UNIT_DEFAULT, mode='grey'):
    """
    Returns a string for a one-page SVG document containing m x m
    Balls.

    * m: number of balls across/down; must be power of 2

    * w: width of page

    * h: height of page

    * unit: specifies measurement unit of w and h.

    * mode: selects shading on the Balls. See the MODES_FNS dict near the
      bottom of this module for a list of all possible choices.

    Example Usage
    =============
    >>> balls_page(8, 210, 297, unit="mm" mode="grey")
    # generates an A4-sized SVG document page with 8x8==64 grey balls

    >>> balls_page(4, 8, 11, unit="in" mode="color")
    # generates a US Letter-sized page with 16 coloured balls

    """
    if mode not in MODES_FNS:
        choices = tuple(MODES_FNS.keys())
        raise ValueError('mode: please select from {}'.format(choices))
    fn = MODES_FNS[mode]
    if log2(m) % 1 != 0:
        raise ValueError('m, number of balls per row, must be power of two')
    desc_text = desc_text_fmt.format(n=m, shading=mode)
    desc = desc_fmt.format(desc_text)
    # prepare defs
    defs_list = [_ball_symbol(w/m, h/m, unit=unit),]
    defs_list.extend(GRAD_DEFS[mode])
    defs_cnt = ''
    for d in defs_list:
        defs_cnt = ''.join((defs_cnt, d, '\n'))
    defs = defs_fmt.format(defs_cnt)
    # prepare content
    cont = ''
    c_total = 0
    for iy in range(m):
        y = iy * (h/m)
        for ix in range(m):
            x = ix * (w/m)
            u_id = "ball-{}".format(c_total)
            cont = ''.join((cont, fn(x,y,unit=unit,u_id=u_id,i=c_total), '\n'))
            c_total += 1
    cont = ''.join((desc, defs, cont))
    # prepare and return final SVG code
    dw = q(w, unit)
    dh = q(h, unit)
    svg = svg_s(dw, dh, cont)
    page = ''.join((DOCTYPE, '\n', svg))
    return page

def print_preset_page(size_name, m, mode='grey'):
    # execute command line call
    if size_name in SIZES:
        a = SIZES[size_name]
        print(balls_page(int(m), a[0], a[1], unit=a[2], mode=mode))
    else:
        msg = "SIZE_NAME must be one of the following: {}".format(
            tuple(sizes.keys())
        )
        print(msg, file=stderr)

BW_GRAD_DEFS = (
        _rad_gradient_def(grad_a, rg_id=0),
        _rad_gradient_def(grad_b, rg_id=1),
)
COLOR_GRAD_DEFS = (
        _rad_gradient_def(grad_rb_a, rg_id=0),
        _rad_gradient_def(grad_rb_b, rg_id=1),
)
GRAD_DEFS = {
    'black': [],
    'grey': [],
    'gray': [],
    'color': [],
    'colour': [],
    'bw-radial-gradient': BW_GRAD_DEFS,
    'color-radial-gradient': COLOR_GRAD_DEFS,
    'colour-radial-gradient': COLOR_GRAD_DEFS,
}
MODES_FNS = {
    'black': _black_flat_ball,
    'grey': _grey_flat_ball,
    'gray': _grey_flat_ball,
    'color': _color_flat_ball,
    'colour': _color_flat_ball,
    'bw-radial-gradient': _gradi_ball,
    'color-radial-gradient': _gradi_ball,
    'colour-radial-gradient': _gradi_ball,
}
# PROTIP: MODES_FNS is placed after the function definitions because it
# references the functions as objects, but before the command line code below
# because it shares the same module-level scope.
# It could have been placed before balls_page(), but that would have made
# this module somewhat harder to read.

if __name__ == '__main__':
    parser_spec = {
        'desc': 'Generate SVG sample pages for printer compression tests',
        'args': {
            '--size': {
                'choices': SIZES.keys(),
                'required': True,
            },
            '--balls-per-row': {
                'type': int,
                'default': 2,
                'help': 'balls per row and column, must be a power of 2',
            },
            '--mode': {
                'choices': MODES_FNS.keys(),
                'default': next(iter(MODES_FNS.keys())),
            },
        },
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
    print_preset_page(size_name=args.size, m=args.balls_per_row, mode=args.mode)

