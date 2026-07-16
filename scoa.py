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
# 0.4 WIP (refactored 2nd Edition SCoADecoder)
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
from enum import Enum
from io import BytesIO
from itertools import chain
from os.path import expanduser

## Revised SCoA Decoder (2026)
## ===========================
class SCoACommand(Enum):
        COPY_RAW         = 0b00     # CopyThenRaw (<=7B)
        COPY_REPEAT      = 0b01     # CopyThenRepeat (<=7B)
        REPEAT_RAW       = 0b11     # RepeatThenRaw (<=7B)
        LONG_COPY_RAW    = 0b10000  # Copy(8-255B)ThenRawLong
        LONG_COPY_REPEAT = 0b10001  # Copy(8-255B)ThenRepeatLong
        LONG_COPY_ONLY   = 0b10011  # Copy(8-255B)?-only opcode
        LONG_REPEAT_RAW  = 0b10100  # Repeat(8-255B)ThenRawLong
        REPEAT_LONG_RAW  = 0b10101  # RepeatThenRaw(8-255B)Long
        COPY_LONG_REPEAT = 0b10110  # CopyThenRepeat(8-255B)Long
        COPY_LONG_RAW    = 0b10111  # CopyThenRaw(8-255B)Long
        LONG_COPY_LONG_REPEAT = 0b10010110
            # Copy(8-255B)ThenRepeat(8-255B)Long
        LONG_COPY_LONG_RAW    = 0b10010111
            # Copy(8-255B)ThenRaw(8-255B)Long
        COPY_ONLY             = 0b111111110
           # Accessed from RepeatThenRaw with 0 rep or 0 raw
        EXTEND = 0b10011111 # 0x9F
        NOP    = 0b01000000 # 0x40, == /COPY_REPEAT?copy=0&repeat=0
        EOL    = 0b01000001 # 0x41, == /COPY_REPEAT?copy=1&repeat=0
        EOP    = 0b01000010 # 0x42  == /COPY_REPEAT?copy=2&repeat=0

class SCoADecoder2:
    """
    Decoder for SCoA-compressed 1-bit (8px/byte) rasters.
    This is a refactored version of the original SCoADecoder,
    designed to be easier to understand and debug.

    Please note that this decoder still does not perform
    extraction from CAPT packets, please use the CAPTStream
    module to extract the compressed data from job files.
    """
    MASK_COUNT_L = 0b00111000
    MASK_COUNT_R = 0b00000111
    MASK_3MS = 0b11100000  # three most significant
    MASK_2MS = 0b11000000  # two most significant
    MASK_COUNT = 0b00011111
    EXTEND_BYTES = 248

    def __init__(self, bpl):
        self._buffer = BytesIO()  # line buffer/memory
        self._precount_a = 0
        self._precount_b = 0
        self._precount_copy = 0
        self.bytes_per_line = bpl
        self.command = None
        self.eop = False   # when True, prevent decode()
        self.input_offset = 0
        self.output_bytes = 0

    def __str__(self):
        return "{}: {}Bpl, in_offset: {}, Command:{}, EOP: {}".format(
            type(self).__name__,
            self.bytes_per_line,
            hex(self.input_offset),
            self.command,
            self.eop
        )

    def __repr__(self):
        return f"<{self.__str__()}>"

    def _eop(self):
        """
        Set the End of Page flag, which when set will prevent
        any further decoding by raising an Exception
        """
        self.eop = True

    def _exe(self, count_cp, count_rep, count_raw, ib):
        """
        Executes commands, writes decoded bytes to buffer,
        returns buffer offset and length of written bytes.
        """
        # This method assumes, based on observation, that
        # copies always come before repeats, which in turn
        # always come before uncompressed/raw bytes.
        #
        self._reset_buffer_position()
        off = self._buffer.tell()
        to_write = b''
        # prepare repeat bytes
        if count_rep:
            rbyte = next(ib).to_bytes(1)
            to_write = b''.join((to_write, rbyte*count_rep))
        # prepare raw bytes
        if count_raw:
            for y in range(count_raw):
                rawbyte = next(ib).to_bytes(1)
                to_write = b''.join((to_write, rawbyte))
        tbytes = count_cp + count_rep + count_raw
        d = self.bytes_per_line - off   # distance from end of buffer
        if tbytes > d:
            raise Exception(
                "Buffer overflow", hex(self.input_offset)
            )
        else:
            self._buffer.seek(off+count_cp)
            self._buffer.write(to_write)
        self.input_offset += min(count_rep, 1) + count_raw
        self.output_bytes += tbytes
        return (off, tbytes)

    def _reset_cmd_counters(self):
        self._precount_a = 0
        self._precount_b = 0
        self._precount_copy = 0

    def _reset_buffer_position(self):
        if self._buffer.tell() >= self.bytes_per_line:
            self._buffer.seek(0)

    def current_line(self):
        return self.output_bytes // self.bytes_per_line

    def decode(self, ib, in_off=None):
        """
        Given an iter yielding bytes of SCoA-encoded data,
        return an iter yielding bytes of the decompressed
        1-bpp raster.

        This method merely identifies opcodes, which are
        then passed on to _exe() for decoding. Further
        details on how SCoA codes are decoded are described
        in _exe().

        Note that the decoded bytes has to fit within the
        number of bytes reported by remaining_line_bytes(),
        or a RuntimeError will be raised.

        The remaining line bytes counter resets after the
        counter reaches zero.

        """
        # Structure of data commands is as follows:
        #
        # short: 0bCCCLLLRRR
        #   -> op: 0bCCC, count_L: 0bLLL, count_r: 0bRRR
        # long: 0bCCCAAAAA 0bDDLLRRR
        #   -> op: 0bCCCDD, precount_a: 0bAAAAA
        # longer: 0bCCCAAAAA 0bDDDBBBBB 0bEELLLRRR
        #   -> op: 0bCCCDDDEE, precount_b: 0bBBBBB
        #
        # Precounts a and b are bitwise OR-ed with counts L
        # or r, depending on the operation, to decode counts
        # from 8 to 255.
        #
        # NOTE: official op names are now in use;
        #   Old => Copy, New => Raw
        if self.eop:
            raise Exception('Decoding past end of page')
        prefix = 0
        if in_off is not None: self.input_offset = in_off-1
        else: self.input_offset -= 1
        for b in ib:
            self.input_offset += 1
            if prefix > 0xFF:
                raise Exception(
                    'Command decoding aborted', hex(self.input_offset)
                )
            # handle 0x9F control code
            if prefix==0 and b==SCoACommand.EXTEND.value:
                cmd = SCoACommand(b)
                self.command = cmd
                self._precount_copy += self.EXTEND_BYTES
                continue
            # detect if a complete data op has been found
            with_2ms = (prefix << 2) | ((b&self.MASK_2MS) >> 6)
            read_off = 0
            read_len = 0
            if with_2ms in SCoACommand:
                L = (b&self.MASK_COUNT_L)>>3  # left count
                r = (b&self.MASK_COUNT_R)     # right count
                cmd = SCoACommand(with_2ms)
                self.command = cmd
                if cmd==SCoACommand.COPY_RAW:
                    cc = self._precount_copy + r
                    read_off, read_len = self._exe(cc, 0, L, ib)
                elif cmd==SCoACommand.COPY_REPEAT:
                    # Control codes are herein interpreted as
                    # special cases of CopyThenRepeat.
                    # The precount_copy variable is assumed to
                    # never be less than 248
                    cc = self._precount_copy + r
                    if not L and not cc:
                        # NOP (0x40)
                        continue
                    elif not L and r==1:
                        # EOL (0x41)
                        self.command = SCoACommand.EOL
                        read_off, read_len = self._exe(
                            self.remaining_line_bytes(), 0, 0, ib
                        )
                    elif not L and r==2:
                        # EOP (0x42)
                        self._eop()
                        return None
                    else:
                        # CopyThenRepeat
                        read_off, read_len = self._exe(cc, L, 0, ib)
                elif cmd==SCoACommand.REPEAT_RAW:
                    if not L:
                        self.command = SCoACommand.COPY_ONLY
                        cc = self._precount_copy + r
                        # Copy-only command with zero left count
                        read_off, read_len = self._exe(cc, 0, 0, ib)
                    elif not r:
                        self.command = SCoACommand.COPY_ONLY
                        cc = self._precount_copy + L
                        # Copy-only command with zero right count
                        read_off, read_len = self._exe(cc, 0, 0, ib)
                    else:
                        # RepeatThenRaw
                        read_off, read_len = self._exe(0, L, r, ib)
                elif cmd==SCoACommand.LONG_COPY_RAW:
                    cc = self._precount_copy + (self._precount_a|r)
                    read_off, read_len = self._exe(cc, 0, L, ib)
                elif cmd==SCoACommand.LONG_COPY_REPEAT:
                    cc = self._precount_copy + (self._precount_a|r)
                    read_off, read_len = self._exe(cc, L, 0, ib)
                elif cmd==SCoACommand.LONG_COPY_ONLY:
                    cc = self._precount_copy + (self._precount_a|L+r)
                    read_off, read_len = self._exe(cc, 0, 0, ib)
                elif cmd==SCoACommand.LONG_REPEAT_RAW:
                    repc = self._precount_a|L
                    read_off, read_len = self._exe(0, repc, r, ib)
                elif cmd==SCoACommand.REPEAT_LONG_RAW:
                    rawc = self._precount_a|r
                    read_off, read_len = self._exe(0, L, rawc, ib)
                elif cmd==SCoACommand.COPY_LONG_REPEAT:
                    cc = self._precount_copy + r
                    repc = self._precount_a|L
                    read_off, read_len = self._exe(cc, repc, 0, ib)
                elif cmd==SCoACommand.COPY_LONG_RAW:
                    cc = self._precount_copy + r
                    rawc = self._precount_a|L
                    read_off, read_len = self._exe(cc, 0, rawc, ib)
                elif cmd==SCoACommand.LONG_COPY_LONG_REPEAT:
                    cc = self._precount_copy + (self._precount_a|r)
                    repc = self._precount_b|L
                    read_off, read_len = self._exe(cc, repc, 0, ib)
                elif cmd==SCoACommand.LONG_COPY_LONG_RAW:
                    cc = self._precount_copy + (self._precount_a|r)
                    rawc = self._precount_b|L
                    read_off, read_len = self._exe(cc, 0, rawc, ib)
                else:
                    raise Exception('Unknown command',self.input_offset)
                self._buffer.seek(read_off)
                yield self._buffer.read(read_len)
                self._reset_cmd_counters()
                prefix = 0
                self._reset_buffer_position()
            else:
                prefix = (prefix << 3) | ((b&self.MASK_3MS) >> 5)
                if not self._precount_a:
                    self._precount_a = (b&self.MASK_COUNT) << 3
                else:
                    self._precount_b = (b&self.MASK_COUNT) << 3

    def remaining_line_bytes(self):
        remain = self.bytes_per_line - self._buffer.tell()
        if remain < 0:
            raise RuntimeError('Line buffer larger than declared')
        return remain

## OG SCoADecoder
## ===============

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
                else:
                    # work around repeat+new with zero counts,
                    # suspected to be captfilter encoder bugs,
                    # by holding back input iterator and writing
                    # out zeroes instead
                    ub = (0x0 for i in range(nu))
                    nu = 0
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
            elif b & 0xE0 == SCOA_LONG_REPEAT:
                #
                # second byte (no old_Long)
                #
                nl = (b & self.UINT_5_MASK) << 3
                nextb = next(biter)
                self._i_in += 1
                self._b2 = nextb
                if nextb & 0xC0 == SCOA_LR_OLD_NEW_LONG:
                    nu = nl
                    nu |= (nextb & self.UINT_3_MASK_HI) >> 3
                    np |= nextb & self.UINT_3_MASK_LO
                elif nextb & 0xC0 == SCOA_LR_LONG_NEW_REPEAT:
                    nu = nl
                    nu |= nextb & self.UINT_3_MASK_LO
                    nr = (nextb & self.UINT_3_MASK_HI) >> 3
                    rb = next(biter)
                    self._i_in += 1
                elif nextb & 0xC0 == SCOA_LR_OLD_REPEAT_LONG:
                    nr = nl | (nextb & self.UINT_3_MASK_HI) >> 3
                    np |= nextb & self.UINT_3_MASK_LO
                    rb = next(biter)
                    self._i_in += 2
                elif nextb & 0xC0 == SCOA_LR_NEWB:
                    nr = nl | (nextb & self.UINT_3_MASK_HI) >> 3
                    nu = (nextb & self.UINT_3_MASK_LO)
                    rb = next(biter)
                    self._i_in += 1
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
            if nu > 0:
                ub = (next(biter) for i in range(nu))
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

