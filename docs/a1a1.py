"""
Database of Known 0xA1A1 Responses
----------------------------------
This module contains a list of responses from the 0xA1A1 command
from printer devices using the Canon Advanced Printing Technology
command language.

Authors
=======
Compiled by Moses Chong, from information published or submitted by
various contributors, mentioned in embedded comments in the database
below. Contributors are from GitHub unless otherwise specified.

License
=======
Public domain/CC0, no rights reserved

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software
to the public domain worldwide. This software is distributed
without any warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see:
<http://creativecommons.org/publicdomain/zero/1.0/>.

"""
# TODO: Migrate this DB to JSON? Python byte strings could be
# converted to integer arrays...

# Database

# DB Format: the database are just dicts with a short name for
# keys, and a packet dump in the form of a byte string for values.

CAPT_INFO_DB = {
    'lbp1120': b'\xA1\xA1\x14\x00\x00\x03\xDD\x00\x01\x00\xFF\x7F\x10\x00\x00\x00\xFF\xFF\x01\x00', # submitted by @ra1nst0rm3d
    'lbp2900': b'\xA1\xA1\x38\x00\x00\x0B\x31\x2A\x01\x01\xF0\xFF\x40\x00\x04\x00\x41\x00\x01\x00\xD0\x02\x00\x00\x6F\x08\x00\x00\xE4\x0D\x00\x00\x00\x00\x00\x00\xFA\x02\x00\x00\xF6\x04\x00\x00\x28\x3C\x32\x32\x58\x02\x58\x02\x15\x03\x02\x02', # from comment in agalakhov#7 submitted by @freesun78
    'lbp3000': b'\xA1\xA1\x38\x00\x00\x0B\x30\x2A\x02\x00\xF0\xFF\x40\x00\x04\x00\x40\x00\x01\x00\x48\x03\x00\x00\x6F\x08\x00\x00\xE4\x0D\x00\x00\x00\x00\x00\x00\xFA\x02\x00\x00\xF6\x04\x00\x00\x28\x3C\x32\x32\x58\x02\x58\x02\x15\x03\x02\x00', # submitted by @mounaiban
    'lbp3010': b'\xA1\xA1\x40\x00\x00\x0B\xBA\x09\x01\x00\xF0\xFF\x40\x00\x04\x00\x52\x00\x01\x03\x48\x03\x00\x00\x6F\x08\x00\x00\xE4\x0D\x00\x00\x00\x00\x00\x00\xFA\x02\x00\x00\xF6\x04\x00\x00\x32\x32\x32\x32\x58\x02\x58\x02\x1E\x03\x04\x00\x56\x10\x00\x00\x00\x00\x00\x00', # submitted by @missla
    'lbp5200': b'\xA1\xA1\x14\x00\x00\x03\x4D\x03\x01\x00\xF0\xFF\x00\x01\x90\x00\x3B\x00\x01\x00', # submitted by @mounaiban
    'lbp6000': b'\xA1\xA1\x40\x00\x00\x0B\xBC\x09\x01\x00\xF0\xFF\x40\x00\x04\x00\x5C\x00\x01\x03\x38\x04\x00\x00\x6F\x08\x00\x00\xE4\x0D\x00\x00\x00\x00\x00\x00\xFA\x02\x00\x00\x58\x07\x00\x00\x32\x32\x32\x32\x58\x02\x58\x02\x1E\x03\x04\x00\x00\x10\x00\x00\x00\x00\x00\x00', # submitted by @rezaxdi
    'lbp6020': b'\xa1\xa1\x40\x00\x00\x0b\xbd\x09\x01\x01\xf0\xff\x00\x01\x04\x00\x67\x00\x01\x03\x38\x04\x00\x00\x6f\x08\x00\x00\xe4\x0d\x00\x00\x00\x00\x00\x00\xfa\x02\x00\x00\x58\x07\x00\x00\x32\x32\x32\x32\x58\x02\x58\x02\x1f\x04\x04\x00\x00\x14\x02\x00\x00\x00\x00\x00', # submitted by @gbThreepwood
    'lbp7200': b'\xa1\xa1\x40\x00\x00\x0b\xca\x0d\x01\x01\xf0\xff\x00\x02\xa6\x01\x53\x00\x01\xf3\xb0\x04\x58\x02\x6f\x08\x6f\x08\xe4\x0d\x00\x00\xe4\x0d\x00\x00\xfa\x02\x1c\x07\xf6\x04\x0a\x0a\x32\x32\x32\x32\x58\x02\x58\x02\x1e\x05\x05\x00\x00\xf0\x00\x00\xb0\x04\x58\x02',
}
