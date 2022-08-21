# Explanation of the BCD Bug in captdriver
#
# PUBLIC DOMAIN, NO RIGHTS RESERVED
# Foreword by Moses Chong
# Special thanks to Oleg Sazonov
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software
# to the public domain worldwide. This software is distributed
# without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication
# along with this software. If not, see:
# <http://creativecommons.org/publicdomain/zero/1.0/>.
#

# Foreword
# ========
# In src/word.h there is an inline function, BCD(), which converts
# little-endian BCD 16-bit values to an int. However, it doesn't work
# because where shifting was necessary, the original value was shifted
# four bits too far.
#
# The BCD format herein refers to Simple BCD, e.g. 0x99 => 99 (0x63).
# Digits are from 0x0 to 0x9, each digit is interpreted literally.
# See https://en.wikipedia.org/wiki/Binary-coded_decimal#Background
#
# The original and fixed versions have been ported to Python for your
# convenience, so you may independently verify its behaviour.
#
# To access these functions, just `python -im bcd` from a shell and go!
#

ERR_MAX = 'lo and hi must both be less than 255'
ERR_MIN = 'lo and hi must both be zero or positive'

WORD = lambda x, y: (y & 0xFF) << 8 | x & 0xFF # read 16-bit little-endian int

def BCD_le_original(lo, hi):
    # Convert little-endian 16-bit BCD to uint16_t
    # Original Version
    # see BCD() in src/word.h in the captdriver tree
    if lo > 0xFF or hi > 0xFF: raise ValueError(ERR_MAX)
    if lo < 0 or hi < 0: raise ValueError(ERR_MIN)
    a = (hi >> 8) & 0x0F # original value is shifted 4 bits too far and lost
    b = (hi >> 0) & 0x0F
    c = (lo >> 8) & 0x0F # "
    d = (lo >> 0) & 0x0F
    if a > 9 or b > 9 or c > 9 or d > 9: return WORD(lo, hi)
    else: return a * 1000 + b * 100 + c * 10 + d * 1
        # passthru for non-BCD numbers

def BCD_le(lo, hi):
    # Fixed BCD()
    # Edited by O. Sazonov (2022), M. Chong (2022)
    if lo > 0xFF or hi > 0xFF: raise ValueError(ERR_MAX)
    if lo < 0 or hi < 0: raise ValueError(ERR_MIN)
    a = (hi >> 4) & 0x0F
    b = hi & 0x0F # the (>> 0) has been removed as it seems to do nothing
    c = (lo >> 4) & 0x0F
    d = lo & 0x0F
    if a > 9 or b > 9 or c > 9 or d > 9: return WORD(lo, hi)
    else: return a * 1000 + b * 100 + c * 10 + d * 1

