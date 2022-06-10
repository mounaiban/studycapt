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

class CAPTStreamTests(TestCase):

    # extract_packet() tests
    #
    CARRIER_OPCODE = b'\x30\xa0'
    OTHER_OPCODE = b'\x30\xb0'
    END_OPCODE = b'\x30\xD0'
    EXTRACT_PACKET_CASES = {
        'contiguous': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
        'contiguous_truncated': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                END_OPCODE,
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
                END_OPCODE,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
        'fragmented_truncated': {
            'input': b''.join((
                CARRIER_OPCODE, b'\x08\x00', b'\x9a'*4,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9b'*4,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                END_OPCODE,
                OTHER_OPCODE, b'\x08\x00', b'\x00'*4,
                CARRIER_OPCODE, b'\x08\x00', b'\x9c'*4,
            )),
            'expected': b'\x9a\x9a\x9a\x9a\x9b\x9b\x9b\x9b',
        },
    }
    cfi = captstream.CAPTStream(None)
    def test_extract_packets(self):
        for k in self.EXTRACT_PACKET_CASES.keys():
            with self.subTest(test=k):
                tcase = self.EXTRACT_PACKET_CASES[k]
                in_iter = (x for x in tcase['input'])
                sample = bytes(self.cfi.extract_packets(
                    in_iter, self.CARRIER_OPCODE, self.END_OPCODE
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
    cfi = captstream.CAPTStream(None)

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
