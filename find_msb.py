"""
Finding Bit Index of Most Significant Bit

The HiSCoA compression routine in captdriver involves finding the
mathematical bit length of an unsigned integer, not unlike bit_length()
for Python int's.

A "slow" version was implemented in captdriver, which compares all
first n-bit values (e.g. 0x01, 0x02, 0x04, 0x08 ...) from the largest
possible of the "unsigned" type to the smallest.

With 32-bit integers, the worst case involves 93 operations in the main
loop: a comparison, a shift and a subtraction for each iteration, over
31 iterations.

This routine is contained in find_msb() in hiscoa-compress.c, and is
invoked from an inner loop of hiscoa_compress_band() by way of
try_write_longrepeat().

Is a faster version possible, and if it is, will it appreciably improve
performance?

Please keep your suggestions C-friendly. No Python or third-party
functions. Code stolen from other FSF-classified 'free' software
projects is accepted, as long as links are provided and origins
are proven. Use while loops instead of range(), as they convert more
easily to compact and complex C for-loop logic.
 
"""
# Copyright 2020 Moses Chong
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. 

from timeit import timeit
from secrets import randbelow

def guard_val(val, sizeof):
    if(val < 0):
        raise ValueError('sorry, uints only')
    elif val >= 2**(8*sizeof) or val < 0:
        raise ValueError(f"sorry, {8*sizeof}-bit uints only")

def find_msb(val, sizeof=4):
    """
    Original captdriver find_msb() linear search using the most
    literal Python re-implementation possible

    """
    # Python ints are signed auto-sized, so we fake a fixed size with
    # the sizeof argument. Python has no C-style for loop, so a while
    # substitute is used instead.
    # The int.bit_length() method accomplishes this, but where is the
    # fun doing it that way?
    #
    guard_val(val, sizeof)
    if(val == 0):
        return 0
    
    nbits = 8*sizeof
    while(val < (1 << nbits)):
        nbits -= 1

    return nbits + 1

def find_msb_shortcut_dualchoice(val, sizeof=4):
    """
    Same linear search, but with special case for 16-bit numbers 

    This nearly halves the number of operations of 1-16 bit numbers.

    """
    guard_val(val, sizeof)
    if(val == 0):
        return 0
   
    if val <= 0xFFFF:
        nbits = 16
    else:
        nbits = sizeof<<3
    while(val < (1 << nbits)):
        nbits -= 1

    return nbits + 1

def find_msb_shortcut_quadchoice(val, sizeof=4):
    """
    Same linear search, but with more special cases, for 24,
    16 and 8-bit numbers.

    This function was found to be slower than the dual-choice
    version for numbers ~32 bits or smaller

    """
    guard_val(val, sizeof)
    if(val == 0):
        return 0
   
    if val <= 0xFFFFFF:
        nbits = 24
    elif val <= 0xFFFF:
        nbits = 16
    elif val <= 0xFF:
        nbits = 8
    else:
        nbits = sizeof<<3
    while(val < (1 << nbits)):
        nbits -= 1

    return nbits + 1


def find_msb_bisearch(val, sizeof=4):
    """
    Attempted binary search find_msb() with no division

    This routine was found to be frequently slower for numbers
    close to 32 bits in actual value.

    Conversely, it is almost twice as fast for 64-bit numbers,
    and more than twice for 128-bit numbers, so save it for
    your high-precision operations.

    """
    guard_val(val, sizeof)
    nbmax = sizeof<<3
    nbmin = 0
    if(val <= 1):
        return val
    elif(val > (1<<(nbmax))):
        return nbmax
    
    while(nbmax != nbmin+1):
        nbits = nbmax - ((nbmax - nbmin) >> 1)
        e = (1 << nbits)
        if (e > val) and ((1 << nbits-1) < val):
            return nbits
        elif (e < val):
            nbmin = nbits
        else:
            nbmax = nbits
    return nbmax + 1

# Benchmarking stuff
#
SAMPLE_SIZE = 20000
get_sample = lambda s,b:[randbelow(1<<(i%b)) for i in range(s)]
    # Get s random numbers, each up to b bits long
sample_32 = get_sample(SAMPLE_SIZE, 32)

funcs = (   
    find_msb,
    find_msb_shortcut_dualchoice,
    find_msb_shortcut_quadchoice,
    find_msb_bisearch
)

def benchmark(funcs=funcs, sample=sample_32, number=1, sizeof=4):
    """
    Run all functions in funcs using the arguments sample, number
    and sizeof.

    Returns a list of tuples containing timeit running times.
    """
    # Benchmark defaults to using cached random 32-bit numbers
    out = []
    for f in funcs:
        stmt = f"[f(i, sizeof={sizeof}) for i in sample]"
        score = timeit(stmt, number=number, globals=locals())
        out.append((f, score))
    return out

