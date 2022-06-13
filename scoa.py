"""
SCoA Toolkit for Python

Reference implementation for Smart Compression Architecture (SCoA)
encoded 1-bit, PBM P4-like bitmaps as used by select Canon laser
printers.

"""
# Written by Moses Chong
# First edition 2022/05/16
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
# * This module only deals with compression, an upcoming, separate
#   module will handle print data extraction from CAPT job files.
# 
# * The decompression routine in SCoADecoder.decode() is still not
#   quite correct; investigations and remedies are on the way...
#
import pdb
from itertools import chain
from os.path import expanduser

SCOA_OLD_NEW = 0b00 << 6 # uncompressed bytes (old+new)
SCOA_OLD_REPEAT = 0b01 << 6
SCOA_REPEAT_NEW = 0b11 << 6 # compressed + uncompressed bytes (repeat+new)
# CopyLong commands; SCOA_LO opcodes must come after SCOA_LONG_OLDB [_248]
SCOA_LONG_OLDB = 0b100 << 5
SCOA_LONG_OLDB_248 = 0x9F
SCOA_LOLD_NEWB = 0b00 << 6
SCOA_LOLD_REPEAT = 0b01 << 6
SCOA_LOLD_WITH_LONG = 0b101 << 5
SCOA_LOLD_REPEAT_LONG = 0b10 << 6
SCOA_LOLD_NEW_LONG = 0b11 << 6
# RepeatLong commands; SCOA_LR opcodes must come after SCOA_LONG_REPEAT
SCOA_LONG_REPEAT = 0b101 << 5
SCOA_LR_LONG_NEW_ONLY = 0b11 << 6
SCOA_LR_ONLY = 0b10 << 6
SCOA_LR_NEWB = 0b00 << 6
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
        stats = {
            'line_size': self.line_size,
            'i_buf': self._i_buf,
            'i_line': self._i_line,
            'i_in': hex(self._i_in),
            'current_op': self._current_op,
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
        self._buffer = [ord(initv),] * self.line_size
        self._buffer_b = [ord(initv),] * self.line_size
        self._current_op = (0,0,0)
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

        NOTE: The decoder is still not 100% complete and will produce
        a generally-legible but glitched result.

        Example
        -------
        decoder = SCoADecoder(596)    # A4 width
        file_h = open('page-1.scoa.bin', mode='rb')
        decoder_iter = decoder.decode(iter(file_h.read()))
        decoded_bytes = bytes(x for x in decoder_iter)

        An iter is used to avoid having to read entire streams into
        large buffers.

        """
        # current_buf = [self._init_value,] * self.line_size
        self._i_in = 0
        np = 0 # number of bytes from previous line
        npx = 0 # number of 0x9f opcodes (np, extended)
        nl = 0 # pre-count for SCOA_LOLD_WITH_LONG-related opcodes
        nr = 0 # number of bytes to repeat
        nu = 0 # number of uncompressed bytes to pass to output
        rb = 0 # repeating byte as integer value (e.g. 0xFF => 255)
        ub = () # uncompressed byte(s)
        #
        # parsing (like opcode decode)
        for b in biter:
            if b == SCOA_NOP:
                pass
            elif b == SCOA_EOL:
                np = self.line_size - self._i_buf
            elif b == SCOA_EOP:
                return
                # raise StopIteration
            # two-bit opcodes
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
                rb = next(biter)
                nu = b & self.UINT_3_MASK_LO
                ub = (next(biter) for i in range(nu))
                self._i_in += nu
            # three-bit opcodes with two-bit subcommand opcode
            elif b & 0xE0 == SCOA_LONG_OLDB:
                while b == SCOA_LONG_OLDB_248:
                    npx += 1
                    b = next(biter)
                    self._i_in += 1
                if b & 0xE0 == SCOA_LONG_OLDB:
                    # check for the SCOA_LONG_OLDB opcode again,
                    # to handle the case where 0x9f is extending
                    # another SCOA_LONG_OLDB opcode
                    np = (b & self.UINT_5_MASK) << 3
                    b = next(biter)
                    self._i_in += 1
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
                    nl = (b & self.UINT_5_MASK) << 3
                    b = next(biter)
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
                nr = (b & self.UINT_5_MASK) << 3
                nextb = next(biter)
                if nextb & 0xC0 == SCOA_LR_LONG_NEW_ONLY:
                    nu = nr
                    nu |= (nextb & self.UINT_3_MASK_HI) >> 3
                    nr = 0
                    ub = (next(biter) for i in range(nu))
                    self._i_in += nu + 1
                elif nextb & 0xC0 == SCOA_LR_ONLY:
                    nr |= (nextb & self.UINT_3_MASK_HI) >> 3
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
            # TODO: Implement optional halt policy that stops decoding
            # when a line has too many bytes?
            # We are currently using a discard/truncate policy for
            # excess bytes.
            total_np = 248*npx + np
            self._current_op = (total_np, nr, nu)
            for x in self._writeout(np=total_np, nr=nr, rb=rb, ub=ub):
                if self._i_buf >= self.line_size: break
                self._buffer_b[self._i_buf] = x
                yield x
                self._i_buf += 1
            np = 0
            npx = 0
            nr = 0
            nu = 0
            rb = 0
            ub = ()
            if self._i_buf >= self.line_size:
                self._i_line += 1
                self._i_buf = 0
                self._buffer = self._buffer_b.copy()
                # PROTIP: cannot just assign buffer to transfer data

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

