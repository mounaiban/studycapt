"""
Diss for CAPT
-------------

A standalone dissector for raw packet dumps from select Canon laser printers
using the Canon Advanced Printing Technology (CAPT) command language and
protocol. Converts raw packets into human-readable, or standard system-
independent machine-readable formats.

Authors
=======
Written by Moses Chong
Second Edition released 2026/05/20

License
=======
Public domain, no rights reserved

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software
to the public domain worldwide. This software is distributed
without any warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see:
<http://creativecommons.org/publicdomain/zero/1.0/>.

"""

from itertools import chain, count
from json import JSONEncoder
from re import finditer
from docs.a1a1 import DB

# Utilities: Formatters

# remove excess whitespace both around and inside strings
deep_strip = lambda x:' '.join(s for s in x.split() if s)

def hex_to_bytes(s):
    """
    Convert hex dump string s to bytes, interpreting s literally.
    Please group hex digits in pairs, preferably separated by spaces.
    (i.e. "ff 00 ff => \xff\x00\xff")

    """
    hexiter = finditer("[0-9a-fA-F]{2}", s)
    return bytes(int(x.group(),16) for x in hexiter)

def le_16(x):
    """
    Interpret 2-byte byte seq x as little endian int.

    If a single byte sequence is given, the byte is assumed to be low,
    and the high byte is assumed to be zero (0x00). Excess bytes are
    ignored.

    """
    lo = x[0]
    hi = 0x0
    if len(x) == 2: hi = x[1]
    return lo + (hi << 8)

def le_16_hex(x):
    return "0x{v:0{l}X}".format(v=le_16(x), l=len(x)*2)

def le_16_str(x):
    return "{} ({})".format(le_16(x), le_16_hex(x))

def bytes_to_hex(b):
    out = ''
    ints = (int(x) for x in b)
    for c in ('{:02X} '.format(y) for y in ints if y <= 0xFF):
        out = ''.join((out, c))
    return out[:-1]

# Field Specifications

# Please note that the meanings of some fields are speculative and
# may be incorrect. These fields are indicated by a question mark
# (?) in the field's long name.

# format: (FIELD_NAME, OFFSET, SIZE, FUNCTION, FIELD_LONG_NAME, NOTES)
# the FUNCTION prepares the data in the field for presentation in docs
# function args: f(x); x is the data in the field
FIELDS_A1A1 = (
    ('OPCODE', 0, 2, le_16_hex, 'Opcode'),
    ('CAPT_REPLY_SIZE', 2, 2, le_16, 'Reply Size'),
    ('UNKNOWN_A', 4, 1, le_16_hex,'Unknown A'),
    ('CAPT_INFO_FORMAT_VERSION', 5, 1, le_16_hex,
        'CAPT Version Identifier A',
        '0x03 for CAPT 1.0 & 2.0; 0x0B for CAPT 2.1 and later'
    ),
    ('CAPT_PRODUCT_ID', 6, 2, le_16_hex, 'Product ID(?)',
        """Devices with similar model numbers and features
        have similar designations."""
    ),
    ('CAPT_FIRMWARE_VERSION', 8, 2, le_16_hex, 'Firmware Version(?)',
        """Based on comparing two LBP3000 printers with near-identical
        responses except for different values in this field"""
    ),
    ('CAPT_RASTER_BLOCK_SIZE', 10, 2, le_16, 'Print Data Block Size (bytes)'),
    ('CAPT_DEVICE_BUFFERS', 12, 2, le_16, 'Buffers',
        'Buffers are 32KB each; multiply by 32767 to get printer memory size'
    ),
    ('UNKNOWN_B', 14, 1, le_16_hex, 'Unknown B',
        """Suspected to indicate support for colour printing, network,
        additional paper trays & two-sided printing. Format might have
        changed as of CAPT 2.1"""
    ),
    ('UNKNOWN_B2', 15, 1, le_16_hex, 'Unknown B2'),
    ('UNKNOWN_C', 16, 2, le_16_hex, 'Unknown C'),
    ('UNKNOWN_D', 18, 1, le_16_hex, 'Unknown D'),
    ('UNKNOWN_D2', 19, 1, le_16_hex, 'Unknown D'),
    # CAPT 2.1 and later
    ('CAPT_THROUGHPUT', 20, 2, le_16, 'Max. B&W Speed (pages/hour)'),
    ('UNKNOWN_E', 22, 2, le_16_hex, 'Unknown E'),
    ('CAPT_MPT_MAX_W', 24, 2, le_16, 'MP Tray Max. Width (x0.1 mm)'),
    ('CAPT_DUPLEX_MAX_W', 26, 2, le_16, 'Duplex Max. Width (x0.1 mm)',
        """Inferred from section F-21 of LBP72000C manual,
        largest supported size was US Legal"""
    ),
    ('CAPT_MPT_MAX_H', 28, 2, le_16, 'MP Tray Max. Length (x0.1 mm)'),
    ('UNKNOWN_F', 30, 2, le_16_hex, 'Unknown F'),
    ('CAPT_DUPLEX_MAX_H', 32, 2, le_16, 'Duplex Max. Length (x0.1 mm)'),
    ('UNKNOWN_G', 34, 2, le_16_hex, 'Unknown G'),
    ('CAPT_MPT_MIN_WIDTH', 36, 2, le_16, 'MPT Min. Width (x0.1 mm)'),
    ('CAPT_DUPLEX_MIN_WIDTH', 38, 2, le_16, 'Duplex Min. Width (x0.1 mm)'),
    ('CAPT_MPT_MIN_HEIGHT', 40, 2, le_16, 'MPT Min. Length (x0.1mm)'),
    ('CAPT_DUPLEX_MIN_HEIGHT', 42, 2, le_16, 'Duplex Min. Length (x0.1mm)'),
    ('CAPT_NOPRINT_TOP',44,1, le_16,'Top Non-printable Margin Width (x0.1mm)'),
    ('CAPT_NOPRINT_BOTTOM',45,1, le_16,'Bottom Non-printable Margin Width (x0.1mm)'),
    ('CAPT_NOPRINT_LEFT',46,1,le_16,'Left Non-printable Margin Width (x0.1mm)'),
    ('CAPT_NOPRINT_RIGHT',47,1,le_16,'Right Non-printable Margin Width (x0.1mm)',
        """All known devices have identical left and right margins and
        there is not enough information to tell if this field is correctly
        the left or right margin."""
    ),
    ('CAPT_RESOLUTION_X', 48, 2, le_16, 'Horizontal Resolution (dpi)'),
    ('CAPT_RESOLUTION_Y', 50, 2, le_16, 'Vertical Resolution (dpi)',
        """All known devices have identical X and Y resolution;
        there is not enough information to tell if this field
        is correctly the X or Y resolution."""
    ),
    ('CAPT_PROTOCOL_VERSION', 52, 1, le_16, 'CAPT Version Identifier B'),
    ('CAPT_PRINT_ENGINE_TYPE', 53, 2, le_16_hex, 'Print Engine Type(?)',
        """May also be a reference to service manuals for a device.
        Multiple devices with common components have been documented
        within a single service manual."""
    ),
    ('UNKNOWN_I', 55, 1, le_16_hex, 'Unknown I'),
    # CAPT 3.0 and later
    ('UNKNOWN_J', 56, 2, le_16_hex, 'Unknown J'),
    ('UNKNOWN_K', 58, 2, le_16_hex, 'Unknown K'),
    ('CAPT_THROUGHPUT_CMYK',60,2,le_16_hex,'Max Full Colour Speed (pages/hour)',
        """Some CMYK devices use a carousel to swap between different
        coloured cartridges instead of marking the medium with all four
        colours in a single pass. This could save space or sidestep
        the challenges of using multiple photoensitive drums, but slows
        down full-colour printing."""
    ),
    ('UNKNOWN_M', 62, 2, le_16_hex, 'Unknown M'),
)

# Utilities

# A1A1 Database export functions
# Refer to docs/a1a1.py for a description of the database
# format (it's very simple, we promise!).

def offset_column_iter(spec, n=None):
    """
    Return an iter of the start and end byte offsets for
    each field in a field specification. The iter is
    intended for use with Markdown table exports.

    Check the field specs above for a description of the
    format used.
    """
    if not n: n = len(spec)
    i = 0
    for f in spec:
        s = f[1]
        e = s + f[2] - 1
        d = e - s
        if not d:
            yield str(s)
        elif d == 1:
            yield "{}, {}".format(s, e)
        elif d > 1:
            yield "{} - {}".format(s, e)
        else:
            raise ValueError('error in field spec: {}'.format(f))
        i += 1
        if i >= n: return

def md_field_label(field, counter_iter):
    """
    Return markdown field labels, include footnote links on fields
    with notes. The counter_iter is intended to be an itertools.count
    object to number
    """
    if(len(field) > 5): return '{}[^{}]'.format(field[4], next(counter_iter))
    else: return field[4]

def md_footnote(field, counter_iter):
    """Return markdown footnotes"""
    return ('[^{}]:{}\n'.format(next(counter_iter), deep_strip(field[5])))

def db_to_md_table(db, op):
    """
    Create a markdown table from a packet database where the
    packet is of opcode op.

    Arguments
    =========
    * db: database

    * op: opcode as an int

    Example
    =======
    # This example writes a Markdown table of the A1A1 responses
    # from different devices in docs.a1a1.DB
    with(f as open('issue-38.txt', mode='w')):
        write(db_to_md_table(DB, 0xa1a1))

    """
    out = ''
    pad = '--'
    sep = '|'
    comment_count = count()
    foot_count = count()
    fields = CAPTPacketExporter.FIELDS[op]
    md_rows = (
        CAPTPacketExporter(x).value_column_str_iter(fn=le_16_str, pad_value=pad)
        for x in db.values() if le_16(x[0:2]) == op
    )
    md_cols = zip(*md_rows)
    md_col_labels = (md_field_label(x, comment_count) for x in fields)
    md_col_offsets = offset_column_iter(fields)
    md_full_rows = ((chain((x[0],), (x[1],), x[2])) for x in (zip(md_col_offsets, md_col_labels, md_cols)))
    md_row_heads_str = sep.join(x.upper() for x in db.keys())
    md_row_strs = (sep.join(x) for x in md_full_rows)
    out = ''.join((out, 'Offset', sep, 'Variable', sep, md_row_heads_str, '\n', '|{}'.format('--|'*(len(DB)+2))))
    all_row_strs = '\n'.join(md_row_strs)
    comments = ''.join(md_footnote(x, foot_count) for x in fields if len(x) > 5)
    return '\n'.join((out, all_row_strs, comments))

def db_to_json(db, indent=2):
    keys = db.keys()
    je = JSONEncoder(indent=indent)
    inner_dicts = (CAPTPacketExporter(x).dict() for x in db.values())
    outer_dict = dict(zip(keys, inner_dicts))
    return je.encode(outer_dict)

# CAPTPacketExporter Class

class CAPTPacketExporter:
    """
    Object representation of a CAPT packet.
    Refer to __init__() for instructions on how to create
    the object.

    Currently, only responses to the 0xA1A1 command are
    supported.
    """

    FIELDS = {
        0xA1A1: FIELDS_A1A1, # a.k.a CAPT_IDENT
    }

    def __init__(self, rb):
        """
        Arguments:
        * rb: the packet data as a byte string

        Example use of a packet object:
        b = CAPT_PACKET_BYTES
        CAPTPacketExporter(b)
        b.dict()   # create a dict version of the packet

        The exporter will automatically detect and load the
        field specification based on the first two bytes of
        the packet.

        """
        if type(rb) is not bytes:
            raise TypeError('only byte arrays are accepted')
        elif le_16(rb[:2]) not in self.FIELDS:
            raise ValueError('unknown command in packet')

        self._blob = rb
        self._fields = self.FIELDS[le_16(rb[:2])]
        # fields to be populated by self._setup()
        self._end_field = None # index of the first absent field
        self.reply_size = None

        self._setup()
        if len(self) != self.reply_size:
            fmt = 'packet size mismatch, expected: {}, actual {}'
            raise ValueError(fmt.format(self.reply_size, len(self)))

    def __len__(self):
        return len(self._blob)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self._blob)

    def _setup(self):
        self.reply_size = le_16(self._blob[2:4])
        # find the last field
        for i in range(2, len(self._fields)):
            # TODO: replace with binary search
            if self._fields[i][1] >= self.reply_size:
                self._end_field = i
                return
        self._end_field = len(self._fields)

    def _validate_fields(self):
        """
        Check if offsets and sizes in the field specs are in
        order.

        PROTIP: use to diagnose mysterious IndexErrors
        """
        i = 0
        try:
            for k in self._fields:
                assert k[1] == i
                i += k[2]
        except AssertionError:
            print('please check offset: {}'.format(k))

    def value_column_iter(self, n=None, fn=None, pad_value=None):
        """
        Return a iterator of formatted values from the field
        spec.

        Arguments:
        * n: number of fields to return

        * fn: use this formatting function instead of the one
              specified in the field specs

        * pad_value: value to use when the packet does not have
                     enough bytes to cover all fields in the
                     spec.

        """
        out = None
        k = n
        if not k: k = self._end_field
        if not fn:
            out = (x[3](self._blob[x[1]:x[1]+x[2]]) for x in self._fields[:k])
        else:
            out = (fn(self._blob[x[1]:x[1]+x[2]]) for x in self._fields[:k])
        if pad_value:
            return chain(out, (pad_value for x in range(len(self._fields)-self._end_field)))
        else: return out

    def value_column_str_iter(self, n=None, fn=None, pad_value=None):
        """
        Return an iter of the field values as strings, in the
        same order as the field specs. The iter is intended for
        use with table exports.

        """
        return (str(x) for x in self.value_column_iter(n, fn, pad_value))

    def offset_column_iter(self, n=None):
        return offset_column_iter(self._fields, n)

    def dict(self, n=None, fn=None):
        """
        Return a dict representation of the packet. The field
        names from the specification is used as the keys to
        the values of the dict.

        """
        k = n
        if not k: k = self._end_field
        return dict(zip(self.keys(),self.value_column_iter(n=k, fn=fn)))

    def keys(self):
        """
        Return an iter of the short field names from the field
        spec, in order of appearance on the spec.

        """
        return (x[0] for x in self._fields)

    def long_names(self):
        """
        Return an iter of the long field names from the field
        spec, in order of appearance on the spec.

        """
        return (x[4] for x in self._fields)

    def print_info(self):
        z = zip(
            (x[4] for x in self._fields),
            self.value_column_iter(fn=le_16_str)
        )
        for d in z:
            print("{}: {}".format(d[0], d[1]))

# TODO: Command-line Executable Stuff
