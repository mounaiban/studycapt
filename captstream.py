#! /bin/python
"""
CAPT Job File and Stream Toolkit for Python

Reference implementation for manipulating CAPT files and CAPT
data streams, used by select Canon laser printers as a container
and transport format for print data.

"""
# Written by Moses Chong
# 0.1 released 2022/05/16
# 0.4 completed 2022/07/26 (add stdin support)
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
# This module contains deprecated and obsolete code and documentation,
# which will be progressively redacted in subsequent releases.
# Please refer to earlier commits if access to historical information
# is required.
#
# The routines in this module are still rather inefficient, especially
# with files containing a large number of pages. This module is
# currently sufficient for development use only, and not intended for
# end user products.
#

import pdb
import os.path
from argparse import ArgumentParser
from collections import OrderedDict
from struct import unpack
from sys import stdin, stdout

try:
    from scoa import SCoADecoder
except ModuleNotFoundError:
    SCoADecoder = None


## Revised CAPTStream (2026)
## =========================

class CAPTStream2:
    """
    Interface for reading data from CAPT job files and streams
    that promises to be more elegant and efficient than the OG
    CAPTStream
    """

    # Informal Summary of CAPT Job Stream Layout
    # (Revised 2026 Edition)
    #
    # CAPT job files/streams are produced by the captfilter
    # command from the official CAPT Linux driver.
    # The captfilter command converts netpbm rasters into
    # CAPT job files.
    #
    # A CAPT job stream is basically a series of CAPT packets
    # back-to-back. Recall that each packet has a two-byte
    # type identifier followed by the size of the entire
    # packet. These packets are identical in structure to
    # the commands sent to the printer, and the responses
    # from the printer.
    #
    # CAPTFILE := [PACKET0...PACKETn]
    # PACKET:= [TYPE, SIZE, [PAYLOAD]]
    #
    # CAPT streams begin with a job info packet (0x0001),
    # immediately followed by one or more pages/images.
    #
    # Each image begins with a page info packet (0x0002),
    # followed by several page prologue commands, depending
    # on the printer device. The image data ("video data" in
    # Canon literature) is contained in multiple packets.
    # A CAPT 1.x job contains SCoA-encoded data in 0xC0A0
    # packets, while a CAPT 2.x or 3.x job contains Hi-SCoA-
    # encoded images in 0x8000 packets.
    #
    # Images end with one or more control packets depending
    # on the printer, and finally with a 0x0004 packet.
    #
    # Job files end with a 0x0003 packet.
    #
    HEADER_LENGTH = 4
    SIZE_TO_TBL_MODEL = {24:'1', 40:'2|3'}

    def __init__(self, stream):
        self.stream = stream

    def packets(self):
        # returns an iter of CAPT packet headers from the stream
        self.stream.seek(0)
        head = b'\x00'
        try:
            while(head):
                head = self.stream.read(self.HEADER_LENGTH)
                pack = CAPTPacket(head, self.stream.tell())
                yield pack
                self.stream.seek(self.stream.tell()+pack.data_length)
                    # skip data stream
        except ValueError:
            return

    def get_job_info(self):
        self.stream.seek(0)
        pk_01= next(self.packets())
        jinfo = self.get_packet_data(pk_01)
        return {
            'CNTblModel': self.SIZE_TO_TBL_MODEL.get(pk_01.length),
            'dump': jinfo
        }

    def get_packet_data(self, packet):
        if type(packet) is not CAPTPacket:
            raise TypeError('packet must be a CAPTPacket object')
        off = packet.data_offset()
        if off:
            self.stream.seek(off)
            return self.stream.read(packet.data_length)
        else: return None

class CAPTPacket:
    """
    Reference to a packet in a CAPT Job Stream, for use with
    the CAPTStream2 class
    """
    HEADER_SFMT = "<HH"
    MIN_SIZE = 4
    OPCODE_TO_NAME = {
        0x0001: 'JOB_INFO',
        0x0002: 'PAGE_METADATA',
        0x0003: 'END_STREAM',
        0x0004: 'END_PAGE',
        0x8000: 'IC_VIDEO_DATA <Hi-SCoA on host>',
        0xC0A0: 'IC_VIDEO_DATA',
        0xC0A4: 'IC_BLACK_END',   # Hi-SCoA only
        0xD0A0: 'IC_BEGIN_PAGE',
        0xD0A4: 'IC_BLACK_PLANE', # Hi-SCoA init
        0xD0A1: 'IC_BEGIN_DATA',
        0xD0A2: 'IC_END_PAGE'
    } # thanks @ValdikSS for 0xC0 and 0xD0 opcode names

    def __init__(self, b, offset):
        # NOTE: offset is for the beginning of the packet,
        #  not the data payload
        if type(b) is not bytes:
            raise TypeError('b must be a byte array')
        elif len(b) < self.MIN_SIZE:
            raise ValueError('b must be at least 4 bytes long')
        p, L = unpack(self.HEADER_SFMT, b[:4])
        if L < self.MIN_SIZE:
            raise ValueError('CAPT packet size must be 4 or larger')
        self.packet_type = p
        self.length = L
        self.offset = offset
        self.data_length = max(L-self.MIN_SIZE, 0)

    def __str__(self):
        return "{}: {} ({}); {}B @ {}".format(
            type(self).__name__,
            self.OPCODE_TO_NAME.get(self.packet_type, ''),
            hex(self.packet_type),
            self.length,
            hex(self.offset)
        )

    def data_offset(self):
        if self.data_length <= 0: return None
        else: return self.offset + self.MIN_SIZE+1

def list_packets(path):
    # List packets in job file at path
    # To obtain a job file, run:
    # captfilter --CNTblModel $M $IN_FILE > $OUT_FILE
    # $M is either 0, 1 or 2.
    # Other options found to work include:
    # --Collate [True|False]
    # --CNCopies  0..2^32-1   (CAPT supports >4 billion copies)
    # --InputSlot [Auto|Manual|Cas1|Cas2|Cas3|Cas4]
    #
    with open(path, mode='rb') as f:
        for p in CAPTStream2(f).packets():
            print(p)

## OG CAPTStream
## =============

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
    # NOTE: This summary was found to be inaccurate after further
    #  studies on the structure of the job files
    #
    # CAPTFILE = [MAGIC, [PAGE0..PAGEn], END]
    # FOOTER = (end-of-page/chunk data)
    # MAGIC = (file type identifier string, FOOTER)
    # PAGE_HEADER = (page handling settings)
    # RASTER_HEADER = (raster metadata, incl. width, height, margins...)
    # RASTER = (compressed raster)
    # HISCOA_PARAMS = (HiSCoA decompression parameters; CAPT 2 only)
    # PAGE = [PAGE_HEADER [,HISCOA_PARAMS], RASTER_HEADER, RASTER, FOOTER]

    MSG_NO_DECODER = 'SCoA Decoder module not found or not enabled'
    MSG_NO_PAGE = 'cannot select page with stdin or other non-seekable streams'
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
            # TODO: Hi-SCOA requires additional arguments which are not
            # yet written out. Extracted pages will not be recoverable.
            'paging_opcodes': [
                    CAPT_RASTER_SETUP, CAPT_HISCOA_PARAMS, HISCOA_RASTER_DATA
                ],
            'page_header_size': 118,
            'raster_data_opcode': HISCOA_RASTER_DATA,
            'raster_end_opcode': CAPT_RASTER_END,
            'codec_name': 'HSCA',
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

        Note on Interactive Shell Usage
        -------------------------------
        CAPTStream will attempt to read from stdin at creation time when
        the path is None. When in interactive mode, type the bytes into
        the console and/or press Enter to continue.

        """
        self.path = path
        self.offsets = []  # see get_offsets() for format
        self._config = None
        self._fh = None
        self._fh_iter = None
        self._set_config(version=version)

    def __del__(self):
        if self._fh is not stdin.buffer: self._fh.close()
        # TODO: is this necessary?

    def _set_config(self, version=None):
        """
        Configures the stream reader to read CAPT streams of a
        particular version.

        The version argument is ignored when the stream reader is
        set to read from a file. In this case, the version is
        inferred from identifiers in the file.
        """
        if not self.path:
            self._fh = stdin.buffer
        else:
            self._fh = open(self.path, mode='rb')
        if version: self._config = self.CONFIG[version]
        else:
            v = self.VERSION_LOOKUP[self._fh.read(MAGIC_SIZE)]
            self._config = self.CONFIG[v]
        return self._config['version']

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

    def extract_packets(self, b, opcode, end_code, n=None, yield_end=False):
        """
        Extract CAPT packets of a specific ``opcode``, from the
        yielded bytes of a byte iterator ``b``. Stop when n packets
        are extracted, or when a terminating opcode ``end_code`` is
        encountered, whichever comes first.

        Returned data is yielded via an iter, byte-by-byte.

        Set n=None to extract all packets in the stream of type
        ``opcode``.

        When ``yield_end`` is True, the contents of the end_code
        packet, if present, is yielded as well. If set to False, the
        iterator will still be advanced to the byte after the
        end_code packet if there are still bytes left in ``b``.

        NOTES
        =====
        CAPT packets have a four-byte header, the first two bytes
        are the opcode and the next two declare the total packet size
        including the header. For details, see the SPECS file in
        captdriver.
        """
        last_byte = next(b)
        i = 0
        k = n or -1
        for x in b:
            if n and i >= k: return
            code = bytes((last_byte, x))
            termi = code == end_code
            if code == opcode or termi:
                vl = next(b)
                vh = next(b)
                vlen = WORD(vl, vh)-4
                if termi and not yield_end:
                    for j in range(vlen): next(b)
                    return
                else:
                    for j in range(vlen): yield next(b)
                if termi: return
                i += 1
            last_byte = x

    def extract_raster_dims(self, b):
        """
        Read dimensions from the next raster found in the stream of
        the byte iter ``b``

        """
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        rast_iter = self.extract_packets(b, CAPT_RASTER_SETUP, None, n=1)
        for i in range(RASTER_LINE_WIDTH_OFFSET): next(rast_iter)
        line_size = WORD(next(rast_iter), next(rast_iter))
        h = WORD(next(rast_iter), next(rast_iter))
        # PROTIP: height is right after line size (fortunately)
        return (line_size, h)

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

    def extract_next_page(self, b, out_format='raw'):
        """
        Extract the first page detected in the byte iter b.
        Return the extracted page as a ready-to-archive byte array
        containing headers and metadata.

        Choices for out_format
        ======================
        'raw': extract data only, do not uncompress

        'p4': uncompress to PBM P4 bitmap

        Note
        ====
        Only CAPT 1.x files are properly supported at the moment

        """
        dims = self.extract_raster_dims(b)
        header = None
        raw_iter = self.extract_raster_packets(b)
        if out_format == 'raw':
            data = bytes(raw_iter)
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
            data = bytes(decoder.decode(raw_iter))
            header = P4_HEADER_FMT.format(w=dims[0]*8, h=dims[1])
        else:
            raise ValueError(self.MSG_UNKNOWN_FORMAT)
        return b''.join((bytes(header, encoding='ascii'), data))

    def get_offsets(self, b):
        """
        Return an iter that yields offsets to page data
        Offsets Table Format Summary
        ============================
        [page_head_off [,hiscoa_params_off], raster_head_off, raster_off]

        page_head_off: Page Header Offset in CAPT file

        """
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        codes = self._config['paging_opcodes']
        for x in self._packet_first_offsets(b, codes):
            yield [x[0]-self._config['page_header_size'], x[0], x[1]]

    def version(self):
        """Return CAPT version as an int"""
        if not self._config: raise ValueError(self.MSG_NO_CONFIG)
        return self._config['version']

    def get_page(self, page=0, out_format='raw'):
        """
        Extract data from a page in the CAPT Job File. To stay in line
        with document processing conventions, the first page is page 1.

        If page is 0, the first page detected will be extracted.

        For a list of supported output formats, see extract_next_page().

        """
        if page:
            if not self._fh.seekable():
                raise IndexError(self.MSG_NO_PAGE)
            if self.path and not self.offsets:
                self._fh.seek(0)
                in_iter = (x for x in self._fh.read())
                self.offsets = [x for x in self.get_offsets(in_iter)]
            if page > len(self.offsets) or page < 1:
                raise IndexError(self.MSG_INVALID_PAGE)
            else:
                self._fh.seek(0)
                self._fh.seek(self.offsets[page-1][1]) # raster setup offset
                self._fh_iter = (x for x in self._fh.read())
        if not self._fh_iter: self._fh_iter = (x for x in self._fh.read())
        return self.extract_next_page(self._fh_iter, out_format=out_format)

def WORD(lo, hi):
    """Get integer from 16-bit little-endian word"""
    # NOTE: Ported from captdriver, see src/word.h
    return (int(hi) << 8) | int(lo)

# Command-line support
ACT_INFO = 'info'
ACT_EXTRACT = 'extract'

def _get_writer(path):
    if path: return open(path, mode='xb')
    else: return stdout.buffer

def _auto_number_filename(path, n):
    b = os.path.basename(path)
    if '.' not in b:
        return "{}.{:04}".format(path, n)
    else:
        bsplit = b.rsplit(os.path.extsep)
        bsplit.insert(-1, "{:04}".format(n))
        f = '.'.join(bsplit)
        if not os.path.dirname(path): return f
        else:
            return "{}{}{}".format(
                os.path.dirname(path), os.path.sep, '.'.join(bsplit)
            )

if __name__ == '__main__':
    parser_spec = OrderedDict({
        'desc': 'View information and extract pages from CAPT job files',
        'args': {
            'action': {
                'help': "select action",
                'choices': (ACT_INFO, ACT_EXTRACT)
            },
            'capt_file': {
                'help': "path to job file; use '-' for standard input"
            },
            '--out_file': {
                'help': 'path to output file (use standard output if not set)'
            },
            '--out_format': {
                'default': 'p4',
                'help': "output format for the 'extract' action",
                'choices': ('raw', 'p4')
            },
            '--page': {
                'default': 0,
                'help': 'select page (use first page if not set)',
            },
            '--num_pages': {
                'default': 1,
                'help': 'pages from & including selected page to process'
            }
        }
    })
    parser = ArgumentParser(description=parser_spec['desc'])
    args_spec = parser_spec['args']
    for k_arg in args_spec:
        sp = args_spec[k_arg]
        parser.add_argument(
            k_arg,
            default=sp.get('default'),
            choices=sp.get('choices'),
            help=sp.get('help')
        )
    args = parser.parse_args()
    in_path = os.path.expanduser(args.capt_file)
    if in_path == '-': in_path = None
    cs = CAPTStream(in_path)
    if args.action == ACT_EXTRACT:
        n = int(args.num_pages)
        p = int(args.page)
        x = p or 1
        try:
            for i in range(p, p+n):
                opath = args.out_file
                if opath and (n > 1):
                    opath = _auto_number_filename(opath, i)
                page = cs.get_page(p, args.out_format)
                with _get_writer(opath) as fh:
                    fh.write(page)
                x += 1
                p = 0 # just get following pages after first page
                      # PROTIP: this does not affect the range iterator
                      # that has already been initialised.
        except StopIteration:
            print("Last page ({}) reached".format(i-1))
    elif args.action == ACT_INFO:
        print("capt_version={}".format(cs._config['version']))
        print("capt_codec={}".format(cs._config['codec_name']))
    else:
        raise NotImplementedError(
            "action '{}' not implemented".format(args.action)
        )
