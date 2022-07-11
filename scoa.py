"""
SCoA Toolkit for Python

Reference implementation for Smart Compression Architecture (SCoA)
encoded 1-bit, PBM P4-like bitmaps as used by select Canon laser
printers.

"""
# Written by Moses Chong
# 0.1 released 2022/05/16
# 0.2 completed 2022/06/13 (opcode support believed to be complete)
# 0.3 completed 2022/06/17 (successfully decompress all test pages to date)
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
# * This module only deals with compression, please use captstream.py
#   to extract print data from job files produced by captfilter.
# 
# * SCoADecoder.decode() is currently being validated. It is now able
#   to decompress all test pages correctly, but further tests are
#   requried to confirm the accuracy of the decoder.
#
import pdb
from itertools import chain
from os.path import expanduser

SCOA_OLD_NEW = 0b00 << 6 # uncompressed bytes (old+new)
SCOA_OLD_REPEAT = 0b01 << 6
SCOA_REPEAT_NEW = 0b11 << 6 # compressed + uncompressed bytes (repeat+new)
# CopyLong commands; SCOA_LOLD opcodes must come after SCOA_LONG_OLDB [_248]
SCOA_LONG_OLDB = 0b100 << 5
SCOA_LONG_OLDB_248 = 0x9F
SCOA_LOLD_NEWB = 0b00 << 6
SCOA_LOLD_REPEAT = 0b01 << 6
SCOA_LOLD_WITH_LONG = 0b101 << 5
SCOA_LOLD_REPEAT_LONG = 0b10 << 6
SCOA_LOLD_NEW_LONG = 0b11 << 6
# RepeatLong commands; SCOA_LR opcodes must come after SCOA_LONG_REPEAT
SCOA_LONG_REPEAT = 0b101 << 5
SCOA_LR_LONG_NEW_REPEAT = 0b01 << 6
SCOA_LR_NEWB = 0b00 << 6
SCOA_LR_OLD_NEW_LONG = 0b11 << 6
SCOA_LR_OLD_REPEAT_LONG = 0b10 << 6
# Control commands
SCOA_NOP = 0x40
SCOA_EOL = 0x41
SCOA_EOP = 0x42

class SCoADecoder:
    """
    SCoA Decoder Object to decompress SCoA streams. SCoA streams
    encode 1-bit rasters very similar in spec to the PBM P4 format.

    Please note that the Decoder does not process file headers or
    other metadata. Metadata must be stripped before the stream is
    passed to the Decoder.

    """
    UINT_3_MASK_HI = 0b00111 << 3
    UINT_3_MASK_LO = 0b00000111
    UINT_5_MASK = 0b00011111

    def __repr__(self):
        # Format for current_op: (np, nr, nu)
        # np - number of bytes from previous line
        # nr - number of repeated new bytes
        # nu - number of new bytes
        op_hex = (hex(x) for x in (self._b1, self._b2, self._b3) if x)
        op_9f = (hex(SCOA_LONG_OLDB_248),) * self._count_9f
        stats = {
            'line_size': self.line_size,
            'i_buf': self._i_buf,
            'i_line': self._i_line,
            'i_in': hex(self._i_in),
            'op': tuple(chain(op_9f, op_hex)),
            'counts': self._counts,
        }
        return "{} <status: {}>".format(self.__class__.__name__, stats)

    def __init__(self, line_size, **kwargs):
        """
        Create an SCoA decoder object.

        The ``line_size`` argument sets the byte length of the output
        bitmap (coincidentially ceiling of pixels/8).

        Keyword Arguments
        -----------------
        * init_value: fill the buffer with this repeating single-byte
          pattern.

        """
        if type(line_size) is not int: raise TypeError('line_size must be int')
        initv = kwargs.get('init_value', b'\x00')
        # validate init value
        if type(initv) is not bytes:
            raise TypeError('init_value must be a single byte')
        elif len(initv) > 1:
            raise ValueError('init_value must be a single byte')

        self.line_size = line_size
        self._init_value = initv
        self._b1 = None # opcode first byte
        self._b2 = None #  second byte
        self._b3 = None #  third byte
        self._buffer = [ord(initv),] * self.line_size
        self._count_9f = 0
        self._counts = (0,0,0)
        self._i_line = 0
        self._i_buf = 0 # indices are in the object, because this allows
        self._i_in = 0  # monitoring to enable progress reports

    # The operations have been found to happen only in this order:
    # old, repeat, new
    #
    # All three operations always run. When an operation is not needed,
    # it still runs but with arguments that render it a non-op.

    def _writeout(self, np=0, nr=0, rb=0, ub=()):
        """
        Return an generator of the expanded form of an SCoA opcode/packet.

        * np: number of old bytes from prev line

        * nr: number of repeated new bytes

        * rb: integer value of byte to repeat (e.g. use 255 for 0xFF)

        * ub: iter of uncompressed new bytes

        """
        iterold = (x for x in self._buffer[self._i_buf : self._i_buf+np])
        iterrep = (rb for x in range(nr))
        iternew = (x for x in ub)
        return chain(iterold, iterrep, iternew)

    def decode(self, biter, debug=False):
        """
        Decompress an iter yielding bytes from an SCoA-compressed
        stream ``biter``.

        Return a generator yielding uncompressed bytes.

        Example
        -------
        decoder = SCoADecoder(596)    # A4 width
        file_h = open('page-1.scoa.bin', mode='rb')
        decoder_iter = decoder.decode(iter(file_h.read()))
        decoded_bytes = bytes(x for x in decoder_iter)

        An iter is used to avoid having to read entire streams into
        large buffers.

        """
        self._i_in = 0
        for b in biter:
            np = 0 # number of bytes from previous line
            npx = 0 # number of 0x9f opcodes (np, extended)
            nl = 0 # pre-count for SCOA_LOLD_WITH_LONG-related opcodes
            nr = 0 # number of bytes to repeat
            nu = 0 # number of uncompressed bytes to pass to output
            rb = 0 # repeating byte as integer value (e.g. 0xFF => 255)
            ub = () # uncompressed byte(s)
            #
            # first byte
            #
            self._b1 = b
            if b == SCOA_NOP:
                pass
            elif b == SCOA_EOL:
                np = self.line_size - self._i_buf
            elif b == SCOA_EOP:
                return
                # raise StopIteration
            elif b & 0xC0 == SCOA_OLD_NEW:
                np = (b & self.UINT_3_MASK_LO)
                nu = (b & self.UINT_3_MASK_HI) >> 3
                ub = (next(biter) for i in range(nu))
                self._i_in += nu
            elif b & 0xC0 == SCOA_OLD_REPEAT:
                np = (b & self.UINT_3_MASK_LO)
                nr = (b & self.UINT_3_MASK_HI) >> 3
                rb = next(biter)
                self._i_in += 1
            elif b & 0xC0 == SCOA_REPEAT_NEW:
                nr = (b & self.UINT_3_MASK_HI) >> 3
                nu = b & self.UINT_3_MASK_LO
                if nr > 0 and nu > 0:
                    rb = next(biter)
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu
                else:
                    # work around repeat+new with zero counts,
                    # suspected to be captfilter encoder bugs,
                    # by holding back input iterator and writing
                    # out zeroes instead
                    ub = (0x0 for i in range(nu))
            elif b & 0xE0 == SCOA_LONG_OLDB:
                #
                # 0x9f or second byte (with old_Long)
                #
                while b == SCOA_LONG_OLDB_248:
                    npx += 1
                    b = next(biter)
                    self._i_in += 1
                if b & 0xE0 == SCOA_LONG_OLDB:
                    # check for the SCOA_LONG_OLDB opcode again,
                    # to handle the case where 0x9f is extending
                    # another SCOA_LONG_OLDB opcode
                    np = (b & self.UINT_5_MASK) << 3
                    self._b1 = b
                    b = next(biter)
                    self._i_in += 1
                self._b2 = b
                if b & 0xC0 == SCOA_LOLD_NEWB:
                    np |= b & self.UINT_3_MASK_LO
                    nu = (b & self.UINT_3_MASK_HI) >> 3
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu
                elif b & 0xC0 == SCOA_LOLD_REPEAT:
                    np |= b & self.UINT_3_MASK_LO
                    nr = (b & self.UINT_3_MASK_HI) >> 3
                    rb = next(biter)
                    self._i_in += 1
                elif b & 0xE0 == SCOA_LOLD_WITH_LONG:
                    #
                    # third byte (with old_Long)
                    #
                    nl = (b & self.UINT_5_MASK) << 3
                    b = next(biter)
                    self._b3 = b
                    self._i_in += 1
                    if b & 0xC0 == SCOA_LOLD_REPEAT_LONG:
                        nr |= nl
                        nr |= (b & self.UINT_3_MASK_HI) >> 3
                        np |= b & self.UINT_3_MASK_LO
                        rb = next(biter)
                        self._i_in += 1
                    elif b & 0xC0 == SCOA_LOLD_NEW_LONG:
                        nu |= nl
                        nu |= (b & self.UINT_3_MASK_HI) >> 3
                        np |= b & self.UINT_3_MASK_LO
                        ub = (next(biter) for i in range(nu))
                        self._i_in += nu
            elif b & 0xE0 == SCOA_LONG_REPEAT:
                #
                # second byte (no old_Long)
                #
                nr = (b & self.UINT_5_MASK) << 3
                nextb = next(biter)
                self._b2 = nextb
                if nextb & 0xC0 == SCOA_LR_OLD_NEW_LONG:
                    nu = nr
                    nu |= (nextb & self.UINT_3_MASK_HI) >> 3
                    nr = 0
                    np |= nextb & self.UINT_3_MASK_LO
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu + 1
                elif nextb & 0xC0 == SCOA_LR_LONG_NEW_REPEAT:
                    nu = nr
                    nu |= nextb & self.UINT_3_MASK_LO
                    nr = (nextb & self.UINT_3_MASK_HI) >> 3
                    rb = next(biter)
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu + 1
                elif nextb & 0xC0 == SCOA_LR_OLD_REPEAT_LONG:
                    nr |= (nextb & self.UINT_3_MASK_HI) >> 3
                    np |= nextb & self.UINT_3_MASK_LO
                    rb = next(biter)
                    self._i_in += 2
                elif nextb & 0xC0 == SCOA_LR_NEWB:
                    nr |= (nextb & self.UINT_3_MASK_HI) >> 3
                    nu = (nextb & self.UINT_3_MASK_LO)
                    rb = next(biter)
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu + 1
            else:
                report = {
                    'offset': self._i_in,
                    'opcode-byte': b
                }
                raise ValueError('unrecognised opcode', report)
            self._i_in += 1
            # writeout (like opcode execution)
            total_np = 248*npx + np
            self._count_9f = npx
            self._counts = (total_np, nr, nu)
            for x in self._writeout(np=total_np, nr=nr, rb=rb, ub=ub):
                self._buffer[self._i_buf] = x
                yield x
                self._i_buf += 1
                if self._i_buf >= self.line_size:
                    # move on to the next line if line is full
                    self._i_line += 1
                    self._i_buf = 0
            self._b1 = None
            self._b2 = None
            self._b3 = None

def _read_scoa_file_header(fh):
    """
    Read Studycapt SCoA-compressed P4 Bitmap Header, return dimensions
    in pixels.

    """
    if fh.readline() != b'SCOA\n':
        raise ValueError('file not marked as SCOA-compressed P4 bitmap')
    width, height = fh.readline().split()
    data_size = fh.readline()
    return (int(width), int(height), int(data_size))

def _scoa_file_iter(path, width=None, data_size=None):
    """
    Return a tuple (file_iter, decoder) where:

    * file_iter is an iter yielding uncompressed bytes from a SCoA-
      compressed P4 bitmap at ``path``. The data does not include
      a header.

    * decoder is a SCoADecoder object decompressing the file at ``path``.

    This function is used for debugging SCoADecoder. Example usage:

    >>> fiter, dec = _scoa_file_iter('comp-page1.scoa')
    >>> dec # shows decoder status
    <decoder status appears>

    >>> next(fiter) # yields the next byte
    <yield next byte>

    >>> [next(fiter) for x in range(10)]
    <yield next ten bytes>

    >>> [next(fiter) for x in range(dec.line_size)]
    <yield bytes until before the same column on the next line>

    """
    with open(expanduser(path), mode='rb') as fh:
        img_w, _, size = _read_scoa_file_header(fh)
        if width: img_w = width
        decoder = SCoADecoder(img_w//8, init_value=b'\xf0')
        return (decoder.decode(iter(fh.read())), decoder)

def scoa_file_to_p4(path, width=None, height=None):
    """
    Return a byte array containing an uncompressed P4 bitmap from a
    SCoA-compressed P4 bitmap file at ``path``.

    Example to decompress a SCoA file to another file:

    out_file = open('page1.pbm', mode='wb') #WARNING: overwrites file on open
    out_file.write(scoa_file_to_p4('comp-page1.scoa'))

    """
    # Input file format
    # -----------------
    # The file format largely follows netpbm conventions, and contains,
    # in this order, from byte 0:
    #
    # The ASCII string "SCOA" (in all caps), then a whitespace character, then
    # The pixel width of the image, then a whitespace char, then
    # The pixel height of the image, then a whitespace char, then
    # The length of the SCoA-compressed bitstream in bytes, then
    # The SCoA-compressed bitstream for the rest of the file.
    #
    # Whitespace character may be space, tab, return, newline, FF, or vtab.
    #
    # Summary:
    # b'SCOA {pixel_width} {pixel_height} {data_bytes} {scoa_data}'
    #
    # Comments are not supported at this time. Only one page per file.
    # TODO: Support multiple pages
    #
    with open(expanduser(path), mode='rb') as scoafile:
        fw, fh, size = _read_scoa_file_header(scoafile)
        if width and height:
            img_w = width
            img_h = height
        else:
            img_w = fw
            img_h = fh
        if img_w % 8 > 0: raise ValueError('width must be divisible by 8')
        if img_h % 8 > 0: raise ValueError('height must be divisible by 8')
        decoder = SCoADecoder(img_w//8, init_value=b'\xf0')
        decoder_iter = decoder.decode(iter(scoafile.read(size)))
        p4_header = "P4\n{} {}\n".format(img_w, img_h)
        out_chain = chain(bytes(p4_header, encoding='ascii'), decoder_iter)
        return bytes(out_chain)

# decoders for manual testing
testdec8 = SCoADecoder(8, init_value=b'\x0f')
testdec255 = SCoADecoder(255, init_value=b'\x0f')
testdec1k = SCoADecoder(255, init_value=b'\x0f')

