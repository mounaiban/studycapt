"""
CAPT Job File and Stream Toolkit (captstream.py) Unit Tests
"""
# Written by Moses Chong
# First edition 2022/06/01
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

from unittest import TestCase
import captstream
from io import BytesIO
import os.path

class CAPTStream2PacketTests(TestCase):
    test_data = BytesIO(b''.join((
        b'\x0a\x67\x0a\x00\x31\x32\x33\x34\x35\x36',  # I @ 0B
        b'\x0b\x67\x06\x00\x00\x00',         # II  @ 10B
        b'\x0c\x67\x08\x00\x41\x42\x43\x44', # III @ 16B
        b'\x0c\x67\x08\x00\x45\x46\x47\x48', # IV  @ 24B
        b'\x0c\x67\x08\x00\x49\x4a\x4b\x4c', # V   @ 32B
        b'\x0d\x67\x04\x00',                 # VI   @ 36B
        b'\x0b\x67\x06\x00\x01\x00',         # VII  @ 40B
        b'\x0c\x67\x08\x00\x4d\x4e\x4f\x50', # VIII @ 46B
        b'\x0c\x67\x08\x00\x51\x52\x53\x54', # IX   @ 54B
        b'\x0d\x67\x04\x00'                  # X    @ 62B
    ))) # BytesIO(b''.join((a,b,c...)))
    test_cstream = captstream.CAPTStream2(test_data)
    test_pkts = tuple(test_cstream._packets())

    def test_packets(self):
        # verify CAPTStream2._packets() under expected conditions
        stats = ((
            x.ptype,
            x.offset,
            x.data_offset(),
            x.length,
            x.data_length
        ) for x in self.test_pkts)
        expected = (             # expected test results
            (0x670A, 0, 4, 10, 6),  # 1. 0x670A @ 0x00, 10B
            (0x670B, 10, 14, 6, 2),  # 2. 0x670B @ 0x0A, 6B
            (0x670C, 16, 20, 8, 4),  # 3. 0x670C @ 0x10, 8B
            (0x670C, 24, 28, 8, 4),  # 4. 0x670C @ 0x18, 8B
            (0x670C, 32, 36, 8, 4),  # 5. 0x670C @ 0x20, 8B
            (0x670D, 40, None, 4, 0), # 6. 0x670D @ 0x28, 4B
            (0x670B, 44, 48, 6, 2),  # 7. 0x670B @ 0x2C, 6B
            (0x670C, 50, 54, 8, 4),  # 8. 0x670C @ 0x32, 8B
            (0x670C, 58, 62, 8, 4),  # 9. 0x670C @ 0x3A, 8B
            (0x670D, 66, None, 4, 0), # 10. 0x670D @ 0x42, 4B
        )
        for x,y in zip(stats, expected):
            self.assertEqual(x,y)

    def test_get_packet_data(self):
        pkt_data = (
            self.test_cstream.get_packet_data(p)
            for p in self.test_pkts
        )
        expected = (
            b'\x31\x32\x33\x34\x35\x36',  # I
            b'\x00\x00',         # II
            b'\x41\x42\x43\x44', # III
            b'\x45\x46\x47\x48', # IV
            b'\x49\x4a\x4b\x4c', # V
            None,                # VI
            b'\x01\x00',         # VII
            b'\x4d\x4e\x4f\x50', # VIII
            b'\x51\x52\x53\x54', # IX
            None,                # X
        )
        for x,y in zip(pkt_data, expected):
            self.assertEqual(x,y)

class CAPTStream2PageTests(TestCase):
    test_data = BytesIO(b''.join((
        # valid job file structure, malformed dummy packets
        b'\x01\x00\x06\x00\x0d\x0c', # job file header   @ 0x00
        b'\x02\x00\x06\x00\x01\x70', # page metadata (1) @ 0x06
        b'\xa0\xd0\x06\x00\x01\x70', # IC_BEGIN_PAGE     @ 0x0C
        b'\xa1\xd0\x04\x00',         # IC_BEGIN_DATA     @ 0x12
        b'\xa0\xc0\x06\x00\x51\x51', # IC_VIDEO_DATA     @ 0x16
        b'\xa0\xc0\x06\x00\x51\x51', # IC_VIDEO_DATA     @ 0x1C
        b'\xa2\xd0\x04\x00',         # IC_END_PAGE       @ 0x22
        b'\x04\x00\x06\x00\x01\x70', # EOP in file   (1) @ 0x26
        b'\x02\x00\x06\x00\x02\x70', # page metadata (2) @ 0x2C
        b'\xa0\xd0\x06\x00\x02\x70', # IC_BEGIN_PAGE     @ 0x32
        b'\xa1\xd0\x04\x00',         # IC_BEGIN_DATA     @ 0x38
        b'\xa0\xc0\x06\x00\x52\x52', # IC_VIDEO_DATA     @ 0x3C
        b'\xa0\xc0\x06\x00\x52\x52', # IC_VIDEO_DATA     @ 0x42
        b'\xa2\xd0\x04\x00',         # IC_END_PAGE       @ 0x48
        b'\x04\x00\x06\x00\x02\x70', # EOP in file   (2) @ 0x4C
        b'\x02\x00\x06\x00\x03\x70', # page metadata (3) @ 0x52
        b'\xa0\xd0\x06\x00\x03\x70', # IC_BEGIN_PAGE     @ 0x58
        b'\xa1\xd0\x04\x00',         # IC_BEGIN_DATA     @ 0x5E
        b'\xa0\xc0\x06\x00\x53\x53', # IC_VIDEO_DATA     @ 0x62
        b'\xa0\xc0\x06\x00\x53\x53', # IC_VIDEO_DATA     @ 0x68
        b'\xa2\xd0\x04\x00',         # IC_END_PAGE       @ 0x6E
        b'\x04\x00\x06\x00\x03\x70', # EOP in file   (3) @ 0x72
        b'\x03\x00\x04\x00'          # end of stream     @ 0x78
    )))
    test_cstream = captstream.CAPTStream2(test_data)

    def test_get_page_first(self):
        content = tuple(
            (x.ptype, x.offset, self.test_cstream.get_packet_data(x))
            for x in self.test_cstream.get_page(1)
        )
        expected = (
            (0x2, 6, b'\x01\x70'),
            (0xD0A0, 12, b'\x01\x70'),
            (0xD0A1, 18, None),
            (0xC0A0, 22, b'\x51\x51'),
            (0xC0A0, 28, b'\x51\x51'),
            (0xD0A2, 34, None),
            (0x4, 38, b'\x01\x70'),
        )
        for x,y in zip(content,expected):
            self.assertEqual(x,y)

    def test_get_page_middle(self):
        content = tuple(
            (x.ptype, x.offset, self.test_cstream.get_packet_data(x))
            for x in self.test_cstream.get_page(2)
        )
        expected = (
            (0x2, 44, b'\x02\x70'),
            (0xD0A0, 50, b'\x02\x70'),
            (0xD0A1, 56, None),
            (0xC0A0, 60, b'\x52\x52'),
            (0xC0A0, 66, b'\x52\x52'),
            (0xD0A2, 72, None),
            (0x4, 76, b'\x02\x70'),
        )
        for x,y in zip(content,expected):
            self.assertEqual(x,y)

    def test_get_page_last(self):
        content = tuple(
            (x.ptype, x.offset, self.test_cstream.get_packet_data(x))
            for x in self.test_cstream.get_page(3)
        )
        expected = (
            (0x2, 82, b'\x03\x70'),
            (0xD0A0, 88, b'\x03\x70'),
            (0xD0A1, 94, None),
            (0xC0A0, 98, b'\x53\x53'),
            (0xC0A0, 104, b'\x53\x53'),
            (0xD0A2, 110, None),
            (0x4, 114, b'\x03\x70'),
        )
        for x,y in zip(content,expected):
            self.assertEqual(x,y)

    def test_refresh_page_index(self):
        self.test_cstream.refresh_page_index()
        idxs = tuple((
            (x[0].ptype, x[0].offset, x[1].ptype, x[1].offset)
            for x in self.test_cstream.pages
        ))
        expected = (
            #startpkt type, startpkt offset, endpkt type, endpkt offset
            (0x2, 6, 0x4, 38),
            (0x2, 44, 0x4, 76),
            (0x2, 82, 0x4, 114),
        )
        for x,y in zip(idxs, expected):
            self.assertEqual(x,y)

class CAPTStreamTests(TestCase):

    # extract_packet() tests
    #
    CARRIER_OPCODE = b'\x30\xa0'
    OTHER_OPCODE = b'\x40\xb0'
    END_OPCODE = b'\x50\xd0'
    EXTRACT_PACKET_CASES = {
        'contiguous': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x04\x00',
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
        'contiguous_n': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x04\x00',
            )),
            'n': 1,
            'expected': b'\x9a\x9a\x9a\x9a',
        },
        'contiguous_n_yield_end': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x06\x00', b'\x9c'*2,
            )),
            'n': 1,
            'yield_end': True,
            'expected': b'\x9a\x9a\x9a\x9a',
        },
        'contiguous_n_yield_early_end': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x06\x00', b'\x9c'*2,
                CARRIER_OPCODE, b'\x08\x00', b'\x9c'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9d'*4,
            )),
            'n': 4,
            'yield_end': True,
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b\x9c\x9c',
        },
        'contiguous_yield_end': {
            'yield_end': True,
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x06\x00', b'\x9c'*2,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b\x9c\x9c',
        },
        'contiguous_truncated': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x04\x00',
                CARRIER_OPCODE, b'\x08\x00', b'\x9c'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9d'*4,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
        'fragmented': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE, b'\x04\x00',
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
        'fragmented_truncated': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                END_OPCODE, b'\x04\x00',
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9c'*4,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
    }
    cfi = captstream.CAPTStream(None, version=1)
    def test_extract_packets(self):
        for k in self.EXTRACT_PACKET_CASES.keys():
            with self.subTest(test=k):
                tcase = self.EXTRACT_PACKET_CASES[k]
                n = tcase.get('n')
                yend = tcase.get('yield_end', False)
                in_iter = (x for x in tcase['input'])
                sample = bytes(self.cfi.extract_packets(
                    in_iter, self.CARRIER_OPCODE, self.END_OPCODE, n, yend
                ))
                expected = tcase['expected']
                self.assertEqual(sample, expected)

    # packet_first_offsets() tests
    #
    TOP_A = b'\x30\xA0'
    TOP_B = b'\x30\xB0'
    TOP_C = b'\x30\xC0'
    ALL_OPCODES = [TOP_A, TOP_B, TOP_C]
    PFO_CASES = {
        'normal_start_at_i_zero': {
            'input': b''.join((
                    # format: opcode, byte_length (uint16_t LE), payload
                    TOP_A, b'\x06\x00', b'\x9a'*2,
                    TOP_B, b'\x07\x00', b'\x9a'*3,
                    TOP_C, b'\x08\x00', b'\x9a'*4,
                )), # PROTIP: single tuple as argument
            'expected': [[0, 6, 13],],
        },
        'normal_start_at_i_nonzero': {
            'input': b''.join((
                    b'\x9a\x9a\x9a\x9a',
                    TOP_A, b'\x06\x00', b'\x9a'*2,
                    TOP_B, b'\x07\x00', b'\x9a'*3,
                    TOP_C, b'\x08\x00', b'\x9a'*4,
                )),
            'expected': [[4, 10, 17],],
        },
        'repeated_packets': {
            'input': b''.join((
                    TOP_A, b'\x06\x00', b'\x9a'*2,
                    TOP_B, b'\x07\x00', b'\x9a'*3, # i==6
                    TOP_B, b'\x07\x00', b'\x9a'*3, # i==13
                    TOP_B, b'\x07\x00', b'\x9a'*3, # i==20
                    TOP_C, b'\x08\x00', b'\x9a'*4, # i==27
                )),
            'expected': [[0, 6, 27],],
        },
        'multiple_cycles': {
            'input': b''.join((
                    TOP_A, b'\x06\x00', b'\x9a'*2,
                    TOP_B, b'\x06\x00', b'\x9a'*2,
                    TOP_C, b'\x06\x00', b'\x9a'*2,
                    TOP_A, b'\x06\x00', b'\x9a'*2,
                    TOP_B, b'\x06\x00', b'\x9a'*2,
                    TOP_C, b'\x06\x00', b'\x9a'*2,
                )),
            'expected': [[0, 6, 12], [18, 24, 30]],
        },
        'opcode_like_content': {
            'input': b''.join((
                    TOP_A, b'\x08\x00', b''.join((TOP_C, b'\x04\x00')),
                    TOP_B, b'\x08\x00', b''.join((TOP_B, b'\x04\x00')),
                    TOP_C, b'\x08\x00', b''.join((TOP_A, b'\x04\x00')),
            )),
            'expected': [[0, 8, 16],],
        },
    }
    cfi = captstream.CAPTStream(None, version=1)

    def test_packet_first_offsets(self):
        for k in self.PFO_CASES.keys():
            with self.subTest(test=k):
                tcase = self.PFO_CASES[k]
                in_iter = (x for x in tcase['input'])
                sample = [
                    x for x in self.cfi._packet_first_offsets(
                        in_iter, self.ALL_OPCODES
                    )
                ]
                expected = tcase['expected']
                self.assertEqual(sample, expected)
        
    def test_malformed_input(self):
        raise NotImplementedError('TODO: write malformed input tests')

class CommandLineTests(TestCase):

    # _auto_number_filename() test
    #
    sep = os.path.sep
    xsp = os.path.extsep
    AUTO_NUMBER_FILENAME_CASES = {
        'begin_with_extsep':{
            'args': {
                'path': '{0}dir{0}{1}file'.format(sep, xsp),
                'n': 9,
            },
            'expected': '{0}dir{0}{1}0009{1}file'.format(sep, xsp),
        },
        'single_extension': {
            'args': {
                'path': '{0}dir{0}file{1}ext'.format(sep, xsp),
                'n': 9,
            },
            'expected': '{0}dir{0}file{1}0009{1}ext'.format(sep, xsp)
        },
        'multi_extension': {
            'args': {
                'path': '{0}dir{0}file{1}suf{1}ext'.format(sep, xsp),
                'n': 9,
            },
            'expected': '{0}dir{0}file{1}suf{1}0009{1}ext'.format(sep, xsp),
        },
        'multi_extension_dotted_dir': {
            'args': {
                'path': '{0}dir{1}ext{0}file{1}suf{1}ext'.format(sep, xsp),
                'n': 9,
            },
            'expected': '{0}dir{1}ext{0}file{1}suf{1}0009{1}ext'.format(sep,xsp)
        },
        'rel_begin_with_extsep':{
            'args': {
                'path': '{1}file'.format(sep, xsp),
                'n': 9,
            },
            'expected': '{1}0009{1}file'.format(sep, xsp),
        },
    }

    def test_auto_number_filename(self):
        for k in self.AUTO_NUMBER_FILENAME_CASES.keys():
            with self.subTest(test=k):
                tcase = self.AUTO_NUMBER_FILENAME_CASES[k]
                a = tcase.get('args', {})
                sample = captstream._auto_number_filename(**a)
                expected = tcase['expected']
                self.assertEqual(sample, expected)
