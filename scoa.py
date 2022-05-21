"""
SCoA Toolkit for Python
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

SCOA_OLD_NEW = 0b00_000000 # uncompressed bytes (old+new)
SCOA_OLD_REPEAT = 0b01_000000 # compressed bytes (old+repeat)
SCOA_REPEAT_NEW = 0b11_000000 # compressed + uncompressed bytes (repeat+new)
# CopyLong commands; SCOA_LO opcodes must come after SCOA_LONG_OLDB [_248]
SCOA_LONG_OLDB = 0b100_00000
SCOA_LONG_OLDB_248 = 0x9F
SCOA_LO_NEWB = 0b00_000000
SCOA_LO_REPEAT = 0b10_000000
# RepeatLong commands; SCOA_LR opcodes must come after SCOA_LONG_REPEAT
SCOA_LONG_REPEAT = 0b101_00000
SCOA_LR_LONG_NEW_ONLY = 0b11_000000
SCOA_LR_ONLY = 0b10_000000
SCOA_LR_NEWB = 0b00_000000
# Control commands
SCOA_NOP = 0x40
SCOA_EOL = 0x41
SCOA_EOP = 0x42

class SCoADecoder:
    """
    SCoA Decoder Object to decompress SCoA streams. SCoA streams
    encode 1-bit rasters very similar in spec to the PBM P4 format.

    """
    UINT_3_MASK_HI = 0b00_111_000
    UINT_3_MASK_LO = 0b00_000_111
    UINT_5_MASK = 0b000_11111

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
        self._i_buf = 0 # indices are in the object, because this allows
        self._i_in = 0  # monitoring to enable progress reports

    # The operations have been found to happen only in this order:
    # old, repeat, new
    #
    # All three operations always run. When an operation is not needed,
    # it still runs but with arguments that render it a non-op.

    def _writeout(self, np=0, nr=0, rb=(), ub=()):
        """
        Return an generator of the expanded form of an SCoA opcode/packet.

        * np: number of old bytes from prev line

        * nr: number of repeated new bytes

        * rb: byte to repeat

        * ub: iter of uncompressed new bytes

        TODO: Mismatched line_sizes may lead to StopIteration errors.
        This error condition is yet to be properly handled.

        """
        iterold = (x for x in self._buffer[self._i_buf : self._i_buf+np])
        iterrep = (x for x in rb*nr)
        iternew = (x for x in ub)
        return chain(iterold, iterrep, iternew)

    def decode(self, biter, debug=False):
        """
        Decompress an iter yielding bytes from an SCoA-compressed
        stream ``biter``.

        Return a generator yielding uncompressed bytes.

        NOTE: The decoder is still not quite correct

        Example
        -------
        decoder = SCoADecoder(596)    # A4 width
        file_h = open('page-1.scoa.bin', mode='rb')
        decoder_iter = decoder.decode(iter(file_h.read()))
        decoded_bytes = bytes(x for x in decoder_iter)

        An iter is used to avoid having to read entire streams into
        large buffers.

        """
        current_buf = [self._init_value,] * self.line_size
        self._i_in = 0
        np = 0 # number of bytes from previous line
        npx = 0 # number of 0x9f opcodes (np, extended)
        nr = 0 # number of bytes to repeat
        rb = () # repeating byte (must still be a tuple due to implementation)
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
                n_new = (b & self.UINT_3_MASK_HI) >> 3
                ub = (next(biter) for i in range(n_new))
                self._i_in += n_new
            elif b & 0xC0 == SCOA_OLD_REPEAT:
                np = (b & self.UINT_3_MASK_LO)
                nr = (b & self.UINT_3_MASK_HI) >> 3
                rb = (next(biter),)
                self._i_in += 1
            elif b & 0xC0 == SCOA_REPEAT_NEW:
                nr = (b & self.UINT_3_MASK_HI) >> 3
                rb = (next(biter),)
                n_new = b & self.UINT_3_MASK_LO
                ub = (next(biter) for i in range(n_new))
                self._i_in += n_new
            # three-bit opcodes with two-bit subcommand opcode
            elif b & 0xE0 == SCOA_LONG_OLDB:
                while b == SCOA_LONG_OLDB_248:
                    npx += 1
                    b = next(biter)
                    self._i_in += 1
                # TODO: understanding of old_Long + new may be wrong
                np = (b & self.UINT_5_MASK) << 3
                nextb = next(biter)
                np |= nextb & self.UINT_3_MASK_LO
                if nextb & 0xC0 == SCOA_LO_NEWB:
                    n_new = (nextb & self.UINT_3_MASK_HI) >> 3
                    ub = (next(biter) for i in range(n_new))
                    self._i_in += n_new
                elif nextb & 0xC0 == SCOA_LO_REPEAT:
                    #nr = b & self.UINT_3_MASK_LO
                    nr = (nextb & self.UINT_3_MASK_HI) >> 3
                    rb = (next(biter),)
                    self._i_in += 1
            elif b & 0xE0 == SCOA_LONG_REPEAT:
                nr = (b & self.UINT_5_MASK) << 3
                nextb = next(biter)
                if nextb & 0xC0 == SCOA_LR_LONG_NEW_ONLY:
                    n_new = nr
                    n_new |= (nextb & self.UINT_3_MASK_HI) >> 3
                    nr = 0
                    ub = (next(biter) for i in range(n_new))
                    self._i_in += n_new + 1
                elif nextb & 0xC0 == SCOA_LR_ONLY:
                    nr |= (nextb & self.UINT_3_MASK_HI) >> 3
                    rb = (next(biter),)
                    self._i_in += 2
                elif nextb & 0xC0 == SCOA_LR_NEWB:
                    nr |= (nextb & self.UINT_3_MASK_HI) >> 3
                    n_new = (nextb & self.UINT_3_MASK_LO)
                    rb = (next(biter),)
                    ub = (next(biter) for i in range(n_new))
                    self._i_in += n_new + 1
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
            for x in self._writeout(np=np+(248*npx), nr=nr, rb=rb, ub=ub):
                if self._i_buf >= self.line_size: break
                current_buf[self._i_buf] = x
                yield x
                self._i_buf += 1
            np = 0
            npx = 0
            nr = 0
            rb = ()
            ub = ()
            if self._i_buf >= self.line_size:
                self._i_buf = 0
                self._buffer = current_buf.copy() # PROTIP: cannot just assign

def scoa_file_to_p4(path, width=None, height=None):
    """
    Return a byte array containing an uncompressed P4 bitmap from a
    SCoA-compressed P4 bitmap file at ``path``.

    """
    # Input file format
    # -----------------
    # The file format largely follows netpbm conventions, and contains
    # in this order from byte 0:
    #
    # The ASCII string "SCOA" (in all caps), then a newline, then
    # The pixel width of the image, then a space, then
    # The pixel height of the image, then a newline, then
    # The SCoA-compressed bitstream for the rest of the file
    #
    # Summary: b'SCOA\n{pixel_width} {pixel_height}\n{scoa_data}'
    #
    # Comments are not supported at this time. Only one page per file.
    # TODO: Make standard closer to netpbm, support multiple pages.
    #
    with open(expanduser(path), mode='rb') as fh:
        if fh.readline() != b'SCOA\n':
            raise ValueError('file not marked as SCOA-compressed P4 bitmap')
        if width and height:
            if width % 8 > 0: raise ValueError('width must be divisible by 8')
            if height % 8 > 0: raise ValueError('height must be divisible by 8')
        else:
            width, height = fh.readline().split(b' ')
        img_w = int(width)
        img_h = int(height)
        decoder = SCoADecoder(img_w//8, init_value=b'\xf0')
        decoder_iter = decoder.decode(iter(fh.read()))
        p4_header = "P4\n{} {}\n".format(img_w, img_h)
        out_chain = chain(bytes(p4_header, encoding='ascii'), decoder_iter)
        return bytes(out_chain)

# decoders for manual testing
testdec8 = SCoADecoder(8, init_value=b'\x0f')
testdec255 = SCoADecoder(255, init_value=b'\x0f')
testdec1k = SCoADecoder(255, init_value=b'\x0f')

