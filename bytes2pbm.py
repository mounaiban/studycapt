#! /bin/python
"""
Byte Array to PBM Converter - create 1bpp images from arbitrary input

This function was intended for revealing the contents of printer
rasters, but may also be used for visualisations of bit-level data
manipulation, such as the study of compression algorithms.

This module may be used as a command from a shell.

"""
# Copyright 2020 Moses Chong
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. 

from sys import argv, stderr, stdin
from io import BytesIO
from array import array
from functools import reduce
from warnings import warn

FORMAT_P1 = "P1"

def bytes_to_p1(in_bytes, w, h, fx=None):
    """
    Create a w*h*1bpp PBM image (P1) from a byte array.

    Returns a string containing the image data.

    """
    if (isinstance(w, int)) is False or (isinstance(h, int)) is False:
        raise TypeError('image width and height must be integers')
    elif w <= 0 or h <= 0:
        raise ValueError('image width and height must be 1 or more')
    pxc = w*h
    byl = len(in_bytes)
    if pxc//8 != byl:
        cbyl = pxc//8    # correct byte length
        if cbyl > byl:
            # not enough bytes
            d = cbyl - byl
            in_bytes += b'\x00' * d
            warn(f"{d} extra zero bytes added to input", RuntimeWarning)
        else:
            d = byl - cbyl
            # too many bytes
            in_bytes = in_bytes[:cbyl]
            warn(f"{d} bytes from end of input ignored", RuntimeWarning)
    if pxc % 8 != 0:
        msg = f"w or h should be a multiple of 8 pixels"
        warn(msg, RuntimeWarning)
    effects = {
        None: lambda x : f"{x:0>8b}",
        'invert': lambda x : f"{((1<<8)-1)^x:0>8b}", # zero->light, 1->dark
    }
    bitgen = effects.get(fx, effects[None])
    pixs = map(bitgen, in_bytes)
    join_back = lambda a,x : ''.join((a,x,))
    pixs_pbm = reduce(join_back, pixs)
    return f"{FORMAT_P1}\n{w} {h}\n{pixs_pbm}"

def run(argv):
    """
    Enables use of bytes_to_p1() from a shell

    Usage: cmd width height [effect] file

    * cmd - name of this module file (originally bytes2pbm.py but may be
      different)

    * effect - optional, influences the way bitmaps are generated.
      Currently, the only supported effect is 'invert', which renders
      low bits as light pixels against a dark canvas.

    """
    try:
        fn = argv[-1]
        w = int(argv[1])
        h = int(argv[2])
        effx = argv[3]
        in_bytes = None
        if fn == '-':
            s = (w*h)//8
            msg = f'Enter {s} bytes for use as pixmap, input CTRL-D to end'
            print(msg, file=stderr)
            in_bytes = bytes(stdin.read(), 'utf-8')
            print('', file=stderr)
        else:
            with open(argv[-1], mode='r+b') as finp:
                in_bytes = bytes(finp.read())
        print(bytes_to_p1(in_bytes, w, h, effx))
        print('', file=stderr)
    except IndexError:
        print(f'Usage: {argv[0]} width height [invert] file')
        print('width and height are in pixels, preferably multiples of 8')
        print('Use - as file to use text standard input instead')
        print(f'Example: {argv[0]} W H in_file > out_file')
        print(f'     or: command | {argv[0]} W H - > out_file')

if __name__ == '__main__':
    run(argv)

