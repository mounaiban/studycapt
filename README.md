# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips dedicated
to an ongoing goal of implementing a *superior*® alternative driver for CAPT-only
Canon laser printers.

For now, there's just the following items:

### capt.lua (Wireshark CAPT Dissector)
A Lua dissector which annotates CAPT commands in packet captures in Wireshark.

To use the dissector for a single Wireshark session, run this command in a directory containing ``capt.lua``:
```
$ wireshark -X lua_script:capt.lua
```

The dissector is currently only able dissect packets over USB. CAPT over Ethernet and parallel printer port/IEEE1284 are currently not supported.

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

### in2pbmp4.sh
A script to make PBM P4 images from files, by basically slapping a PBM P4 header
onto an excerpt of the first bytes of a file.

Assuming that ``in2pbmp4.sh`` is already marked as executable with
``chmod +x`` or any alternative method:

```
# Visualise the first 8320 (i.e. 104x80) bytes of a file as a 104x80px image:
$ ./in2bpmp4 104 80 binary_file > visp4.pbm

# Create an A4-sized random 1bpp image (at 600dpi) for compression tests
# Note: the name of the file containing random bits is repeated at two places
$ dd if=/dev/urandom of=random-a4.bin bs=100 count=347944 && ./in2pbmp4 4970 7014 random-a4.bin > random-a4.pbm
```

### sample\_balls.py
A script to generate print test pages in SVG format.

```
# Generate an A4-sized page filled with 16x16 grey ellipses
$ ./sample_balls --size a4 --balls-per-row 16 --mode grey > test_a4_grey.svg

# Generate a US Letter-sized page filled with 2x2 gradient-filled ellipses
$ ./sample_balls --size letter --mode bw-radial-gradient > test_letter_grads.svg

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
