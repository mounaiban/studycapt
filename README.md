# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips dedicated
to an ongoing goal of implementing a *superior*® alternative driver for CAPT-only
Canon laser printers.

For now, there's just the following items:

### find\_msb()
An experiment in improving ``find_msb()``, a function in ``hiscoa-compress.c`` that finds the position of an integer's highest bit, similar to Python's ``int.bit_length()``.

To run the benchmarks:
```
$ python -im find_msb
>>> benchmark()
```
To benchmark with 64-bit and 128-bit numbers:
```
>>> sample_64 = get_sample(100000, 64)
>>> benchmark(sample=sample_64, sizeof=8)
...
>>> sample_128 = get_sample(100000, 128)
>>> benchmark(sample=sample_128, sizeof=16)
```

### bytes2pbm
A script to make PBM P1 images from standard input or files, visualising it
as a 1-bpp bitmap.

Assuming that ``bytes2pbm.py`` is already marked as executable with
``chmod +x bytes2pbm.py`` or any alternative method:

```
# inputs should be (w*h)/8 bytes long, bytes will be ignored or padded
# if the input length is not correct

# visualise a file as a 104x100x1bpp bitmap
$ ./bytes2pbm 104 100 your_file > vis.pbm

# enter text to be visualised as a 16x16 bitmap
$ ./bytes2pbm 16 16 - > message.pbm

# you cannot crib from RNGs as random bytes can be mistaken as malformed strings
$ dd if=/dev/urandom bs=1 count=800 | ./bytes2pbm 80 80 -
...
UnicodeDecodeError: ....

# instead, output such streams to a separate file:
$ dd if=/dev/urandom bs=1 count=800 of=random.bin
$ ./bytes2pbm 80 80 random.bin > random.pbm

```

### in2pbmp4.sh
A script to make PBM P4 images from files, by basically slapping a PBM P4 header
onto an excerpt of the first bytes of a file. PBM P4s are eight times as compact
as a P1, and are recommended when there is no need to tinker with individual bits.

Assuming that ``in2pbmp4.sh`` is already marked as executable with
``chmod +x`` or any alternative method:

```
# Visualise the first (104*80)/8 bytes of a file:
$ ./in2bpmp4 104 80 your_file > visp4.pbm
```

### sample\_balls
A script to generate print test pages in SVG format.

```
# Generate an A4-sized page filled with 16x16 grey ellipses
$ ./sample_balls a4 16 grey > test_a4_grey.svg

# Generate a US Letter-sized page filled with 8x8 gradient-filled ellipses
$ ./sample_balls letter grey-radial-gradient > test_letter_grads.svg

```

Have fun!

## Licensing
Licensing terms may vary between files in this repository, as it may contain
copy-pasted material licensed by other authors.

Please check individual files for licensing terms and conditions, if you wish to
use any code or information in this repository in your own work.

## Links
* Alexey Galakhov's original captdriver repository: https://github.com/agalakhov/captdriver

  * Alexey's CAPT reverse-engineering "scratch repo": https://github.com/agalakhov/anticapt

* My version: https://github.com/mounaiban/captdriver

  * The unofficial Captdriver Wiki! https://github.com/mounaiban/captdriver/wiki
