"""
CAPT Job File and Stream Toolkit for Python

Reference implementation for manipulating CAPT files and CAPT
data streams, used by select Canon laser printers as a container
and transport format for print data.

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

# NOTE
# ====
# The routines in this module are still rather inefficient, especially
# with files containing a large number of pages. This module is
# currently sufficient for development use only, and not intended for
# end user products.
#

import pdb
try:
    from scoa import SCoADecoder
except ModuleNotFoundError:
    SCoADecoder = None

# CAPT spec constants
MAGIC_SIZE = 8
PACKET_HEADER_SIZE = 4
RASTER_LINE_WIDTH_OFFSET = 26
RASTER_HEIGHT_OFFSET = 28
# CAPT opcodes (in Big Endian, order of typical appearance)
CAPT_RASTER_SETUP = b'\xa0\xd0'
CAPT_HISCOA_PARAMS = b'\xa4\xd0'
CAPT_RASTER_SETUP_END = b'\xa1\xd0'
HISCOA_RASTER_DATA = b'\x00\x80'
SCOA_RASTER_DATA = b'\xa0\xc0'
CAPT_RASTER_END = b'\xa2\xd0'
# Captdriver Project-specific data
HEADER_FMT = "{fmt}\n{w} {h}\n{size}\n"
P4_HEADER_FMT = "P4\n{w} {h}\n"

class CAPTStream:
    """Interface for reading data from CAPT job files and streams"""

    # Informal Summary of CAPT Job File (CAPTFILE) layout
    # ===================================================
    # CAPTFILE = [MAGIC, [PAGE0..PAGEn], END]
    # FOOTER = (end-of-page/chunk data)
    # MAGIC = (file type identifier string, FOOTER)
    # PAGE_HEADER = (page handling settings)
    # RASTER_HEADER = (raster metadata, incl. width, height, margins...)
    # RASTER = (compressed raster)
    # HISCOA_PARAMS = (HiSCoA decompression parameters; CAPT 2 only)
    # PAGE = [PAGE_HEADER [,HISCOA_PARAMS], RASTER_HEADER, RASTER, FOOTER]

    MSG_NO_DECODER = 'SCoA Decoder module not found or not enabled'
    MSG_NO_PATH = 'this feature is only for file streams'
    MSG_NO_CONFIG = 'please set format configuration first; see _set_config()'
    MSG_INVALID_PAGE = 'invalid page number'
    MSG_UNKNOWN_FORMAT = 'unsupported or unknown format'
    VERSION_LOOKUP = {
        b'\x01\x00\x18\x00\xCE\xDA\xDE\xFA': 1, # CAPT 1
        b'\x01\x00\x28\x00\xCE\xDA\xDE\xFA': 2, # CAPT 2
    } # magic bytes (0x00 to 0x07) to version number lookup
    CONFIG = {
        1: { # CAPT 1
            'paging_opcodes': [CAPT_RASTER_SETUP, SCOA_RASTER_DATA],
            'page_header_size': 106,
            'raster_data_opcode': SCOA_RASTER_DATA,
            'raster_end_opcode': CAPT_RASTER_END,
            'codec_name': 'SCOA',
            'version': 1,
        },
        2: { # CAPT 2
            'paging_opcodes': [
                    CAPT_RASTER_SETUP, CAPT_HISCOA_PARAMS, HISCOA_RASTER_DATA
                ],
            'page_header_size': 118,
            'raster_data_opcode': HISCOA_RASTER_DATA,
            'raster_end_opcode': CAPT_RASTER_END,
            'codec_name': 'HISCOA',
            'version': 2,
        },
    } # NOTE: keys are int's, not str's

    def __init__(self, path=None, version=None):
        """
        Creating a CAPTStream object:

        capts = CAPTStream(None) => CAPTStream with only stream functions
        capts = CAPTStream('file.capt') => CAPTStream with all functions
                                           accessing data from a file named
                                           'file.capt'
        """
        self.path = path
        self.offsets = []  # see get_offsets() for format
        self._config = None
        if path: self._set_config(version=version)

    def _set_config(self, version=None):
        """
        Configures the stream reader to read CAPT streams of a
        particular version.

        The version argument is ignored when the stream reader is
        set to read from a file. In this case, the version is
        inferred from identifiers in the file.
        """
        if not self.path:
            if version: self._config = self.CONFIG[version]
        if not self._config:
            with open(self.path, mode='rb') as fh:
                version = self.VERSION_LOOKUP[fh.read(MAGIC_SIZE)]
                self._config = self.CONFIG[version]
        return self._config['version']

    def _raster_dims_from_file(self, fh, pg):
        """
        Read raster dimensions from page ``pg`` of the CAPT Job
        file opened by file handle ``fh``.
        """
        off = self.offsets[pg-1][1] # raster metadata
        fh.seek(off + PACKET_HEADER_SIZE + RASTER_LINE_WIDTH_OFFSET)
        w_raw = fh.read(2)
        line_size = WORD(w_raw[0], w_raw[1])
        fh.seek(off + PACKET_HEADER_SIZE + RASTER_HEIGHT_OFFSET)
        h_raw = fh.read(2)
        h = WORD(h_raw[0], h_raw[1])
        return (line_size, h)

    def _packet_first_offsets(self, b, opcodes, bias=0, verify=False):
        """
        Return an iter yielding offsets of CAPT packets of interest
        in a bytes iter ``b``. If there are multiple packets of the same
        type in a row, only the first packet's offset is yielded.

        When there are multiple packet types of interest, the offsets
        are detected in the same order presented in ``opcodes``.

        The ``bias`` value increases (when > 0) or decreases (when < 0)
        every offset discovered by a fixed amount.

        Example: in stream b = s,t,r,0,A,B,C,C,q,r,A,x,y,B,z,C,C,C...
        When ``opcodes`` of interest == [A,B,C] the offsets will be
        ([4,5,6], [10,13,15]).

        If the ``bias`` is set to -4, the offsets will be ([0,1,2], [6,9,11])

        This example shows one-byte opcodes, but CAPT opcodes are
        two-byte. The procedure remains the same regardless.
        """
        # TODO: Implement verify option; this attempts to detect
        # malformed data in job files.
        #
        n_codes = len(opcodes)
        last_code = None
        last_byte = next(b)
        i = 1
        i_op = 0
        offsets = [0,] * n_codes
        for x in b:
            code = bytes((last_byte, x))
            if code == opcodes[i_op]:
                offsets[i_op] = i-1 + bias
                if i_op >= n_codes-1:
                    yield offsets
                    offsets = [0,] * n_codes
                    # PROTIP: lists must be recreated from scratch or the
                    # multiple references to the same list will be yielded,
                    # making results incorrect.
                vl = next(b)
                vh = next(b)
                vskip = WORD(vl, vh)-4 or 1
                for j in range(vskip): next(b)
                i += vskip + 2
                i_op = (i_op+1) % n_codes
            last_code = code
            last_byte = x
            i += 1

    def extract_packets(self, b, opcode, end_code):
        """
        Extract CAPT packets of a specific ``opcode``, exit when
        a terminating packet of opcode ``end_code`` is detected.

        Returned data is yielded via an iter, byte-by-byte.

        NOTES
        =====
        The contents or size of the terminating packet is not read
        for size or content, its mere presence is sufficient to stop
        the extraction.

        CAPT packets have a four-byte header, the first two bytes
        are the opcode and the next two declare the total packet size
        including the header. For details, see the SPECS file in
        captdriver.
        """
        last_byte = next(b)
        for x in b:
            code = bytes((last_byte, x))
            if code == end_code:
                return
                #raise StopIteration
            elif code == opcode:
                vl = next(b)
                vh = next(b)
                vlen = WORD(vl, vh)-4
                for j in range(vlen): yield next(b)

    def extract_raster_packets(self, b):
        """
        Extract CAPT packets from byte iter ``b`` that contain raster
        data. Returned data is yielded via an iter, byte-by-byte.

        Please set the stream reader to match the CAPT version used
        by on stream beforehand, see __init__() and _set_config().
        """
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        op_rast_data = self._config['raster_data_opcode']
        op_rast_end = self._config['raster_end_opcode']
        for x in self.extract_packets(b, op_rast_data, op_rast_end):
            yield x
    
    def get_offsets(self):
        """
        Return an iter that yields offsets to page data
        """
        # Offsets Table Format Summary
        # ============================
        # [page_head_off [,hiscoa_params_off], raster_head_off, raster_off]
        #
        # page_head_off: Page Header Offset in CAPT file
        #
        # TODO: allow detecting offsets of specific pages, and if
        # possible, without needing to find offsets of preceding pages.
        #
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        codes = self._config['paging_opcodes']
        with open(self.path, mode='rb') as fh:
            fit = (x for x in fh.read())
            for x in self._packet_first_offsets(fit, codes):
                x.insert(0, x[0] - self._config['page_header_size'])
                self.offsets.append(x)
        return self.offsets
        
    def version(self):
        """Return CAPT version as an int"""
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        return self._config['version']

    def get_page(self, page=1, out_format='raw'):
        """
        Extract data from a page in the CAPT Job File. To stay in line
        with document processing conventions, the first page is page 1.

        Choices for out_format
        ======================
        'raw': extract data only, do not uncompress

        'p4': uncompress to PBM P4 bitmap

        """
        if not self.path: raise ValueError(self.MSG_NO_PATH)
        if not self.offsets: self.get_offsets()
            # TODO: make layout detection optional; make ``page``
            # argument optional and simply get the next page if
            # there is no page specified.
        if not self.path: raise ValueError(self.MSG_NO_PATH)
        if page > len(self.offsets) or page < 1:
            raise IndexError(self.MSG_INVALID_PAGE)
        with open(self.path, mode='rb') as fh:
            data = None
            header = None
            fmt_name = None
            dims = self._raster_dims_from_file(fh, pg=page)
            fh.seek(self.offsets[page-1][-1]) # raster offset
            in_iter = (x for x in fh.read())
            if out_format == 'raw':
                data = bytes(self.extract_raster_packets(in_iter))
                out_fmt = self._config['codec_name']
                header = HEADER_FMT.format(
                    fmt=out_fmt,
                    w=dims[0]*8,
                    h=dims[1],
                    size=len(data)
                )
            elif out_format == 'p4':
                if not SCoADecoder: ValueError(self.MSG_NO_DECODER)
                decoder = SCoADecoder(line_size=dims[0])
                raw_iter = self.extract_raster_packets(in_iter)
                data = bytes(decoder.decode(raw_iter))
                header = P4_HEADER_FMT.format(w=dims[0]*8, h=dims[1])
            else:
                raise ValueError(self.MSG_UNKNOWN_FORMAT)
            return b''.join((bytes(header, encoding='ascii'), data))

def WORD(lo, hi):
    """Get integer from 16-bit little-endian word"""
    # NOTE: Ported from captdriver, see src/word.h
    return (int(hi) << 8) | int(lo)

