#! /bin/python
"""
Print Test Page Generator: Balls
Create a single-page SVG test print document filled with balls.

The functions in this module are intended for generating test pages to
verify correctness of output, and also to diagnose performance issues
with compression routines.

This module was created for use with Captdriver, but it should be
suitable for testing any other printer driver.

"""
# Written by Moses Chong
# (2021/01/02)
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

from math import log2
from sys import argv, stderr

DOCTYPE = "<?xml version='1.0' encoding='UTF-8' standalone='no' ?>"
GREY = '#999'
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

q = lambda s, unit: f"{s}{unit}" # quantity with unit as string
svg_s = lambda w,h,cont: svg_fmt.format(w,h, XMLNS_SVG, XMLNS_XLINK, cont)
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
    ellipse = f"<ellipse cx='{qx_c}' cy='{qy_c}' rx='{qrx}' ry='{qry}' />"
    symbol = f"<symbol id='{BALL_ID}'>\n{ellipse}\n</symbol>"
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
        idp = ''.join((f"id='{u_id}'", ' ',))
    qx_r = q(x, unit)
    qy_r = q(y, unit)
    use = f"<use {idp}x='{qx_r}' y='{qy_r}' fill='{fill}' xlink:href='#ball'/>"
    return use

def _grey_flat_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a grey ball on the test page.
    Arguments are the same as _ball(), see _ball() for usage.

    NOTE: i is not used in this function; it is included for
    compatibility purposes only.

    """
    return _ball(x, y, '#999', unit=unit, u_id=u_id)

def _color_flat_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a coloured ball on the test page.
    Arguments are the same as those of _ball(), see _ball() for usage.

    * i: sets the colour of the ball, the colour is cycled between
      aqua-cyan, magenta, yellow, black, red, green and blue.

    """
    fills = ('#0ff', '#f0f', '#ff0', '#000', '#f00', '#0f0', '#00f') # CMYKRGB
    k = i % len(fills)
    return _ball(x, y, fills[k], unit=unit, u_id=u_id)

def _gradi_ball(x, y, unit=UNIT_DEFAULT, u_id=None, i=0):
    """
    Returns a string to place a grey radial gradient-filled ball on the
    test page.  Arguments are the same as those of _ball(), see _ball()
    for usage.

    * i: sets the fill of the ball, fills alternate between light-to-dark
      and dark-to-light

    """
    k = i % 2
    fill_url = f"url(#rg-{k})"
    return _ball(x, y, fill_url, unit=unit, u_id=u_id)

def balls_page(m, w, h, unit=UNIT_DEFAULT, mode='grey'):
    """
    Returns a string for a one-page SVG document containing m x m
    Balls.

    * m: number of balls across/down; must be power of 2

    * w: width of page

    * h: height of page

    * unit: specifies measurement unit of w and h.

    * mode: selects shading on the Balls, current choices are
      'grey', 'color' and 'grey-radial-gradient'

    Example Usage
    =============
    >>> balls_page(8, 210, 297, unit="mm" mode="grey")
    # generates an A4-sized SVG document page with 8x8==64 grey balls

    >>> balls_page(4, 8, 11, unit="in" mode="color")
    # generates a US Letter-sized page with 16 coloured balls

    """
    mode_fns = {
        'grey': _grey_flat_ball,
        'color': _color_flat_ball,
        'grey-radial-gradient': _gradi_ball
    }
    if mode not in mode_fns:
        choices = tuple(mode_fns.keys())
        raise ValueError(f'mode: please select from {choices}')
    fn = mode_fns[mode]
    if log2(m) % 1 != 0:
        raise ValueError('m must be power of two')
    desc_text = desc_text_fmt.format(n=m, shading=mode)
    desc = desc_fmt.format(desc_text)
    # prepare defs
    defs_list = [
        _ball_symbol(w/m, h/m, unit=unit),
        _rad_gradient_def(grad_a, rg_id=0),
        _rad_gradient_def(grad_b, rg_id=1),
    ]
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
    sizes = {
        'a4': (210, 297, 'mm'),
        'a5': (148, 210, 'mm'),
        'f4': (215.9, 330, 'mm'),
        'jis-b5': (182, 257, 'mm'),
        'legal': (8.5, 14, 'in'),
        'letter': (8.5, 11, 'in'),
        'sac-16k': (195, 270, 'mm'),
    }
    if size_name in sizes:
        a = sizes[size_name]
        print(balls_page(int(m), a[0], a[1], unit=a[2], mode=mode))
    else:
        msg = f"SIZE_NAME must be one of the following: {tuple(sizes.keys())}"
        print(msg, file=stderr)

if __name__ == '__main__':
    if len(argv) < 3:
        msg = f"Usage: {argv[0]} SIZE_NAME BALLS_PER_ROW [MODE]"
        print(msg, file=stderr)
    else:
        print_preset_page(*argv[1:])

