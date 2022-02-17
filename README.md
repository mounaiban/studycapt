# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips
dedicated to an ongoing goal of implementing a *superior*<sup>®</sup>
alternative driver for CAPT-only Canon laser printers.

For now, there's just the following items:

### [capt.lua](capt.lua) (CAPT/USB Dissector for Wireshark)
A Lua dissector which annotates CAPT commands in packet captures in Wireshark.

To use the dissector for a single Wireshark session, run this command in a
directory containing ``capt.lua``:

```bash
$ wireshark -X lua_script:capt.lua
```

Other ways of adding Lua dissectors are explained in [Chapter 10](https://wireshark.org/docs/wsdg_html_chunked/wsluarm.html) of the Wireshark Developer Guide.

The dissector currently only dissects packets over USB. CAPT over Ethernet and
parallel printer/IEEE 1284 ports are currently not supported.

### [find\_msb()](find_msb.py)
An experiment in improving ``find_msb()``, a function in ``hiscoa-compress.c``
that finds the position of an integer's highest bit, similar to Python's
``int.bit_length()``.

To run the benchmarks:

```bash
$ python -im find_msb
```

To benchmark with 64-bit and 128-bit numbers:

```python
>>> benchmark()
>>> sample_64 = get_sample(100000, 64)
>>> benchmark(sample=sample_64, sizeof=8)
...
>>> sample_128 = get_sample(100000, 128)
>>> benchmark(sample=sample_128, sizeof=16)
```

### [in2pbmp4.sh](in2pbmp4.sh) (Input to PBM/P4 Image Script)
A script to make PBM P4 images from any file, by slapping a PBM P4 header onto
an excerpt of the first bytes of a file.

Assuming that ``in2pbmp4.sh`` is already marked as executable with
``chmod +x`` or any alternative method:

```bash
# Visualise the first 1040 (i.e. 104x80/8) bytes of a file as a 104x80px image:
$ ./in2bpmp4 104 80 binary_file > visp4.pbm

# Create an A4-sized random 1bpp image (at 600dpi) for compression tests
# Note: the name of the file containing random bits is repeated at two places
$ dd if=/dev/urandom of=random-a4.bin bs=100 count=347944 && ./in2pbmp4 4970 7014 random-a4.bin > random-a4.pbm
```

You can easily create 1-bit (pseudo-)random noise images with this script, these
are not compressible by conventional compression algorithms. Such images may be
used for studying out-of-memory behaviours of printers.

### [sample\_balls.py](sample_balls.py) (Performance Test Page Generator)
A script to generate test pages of varying complexity in SVG format, in order
to test rasteriser and compressor performance.

```bash
# Generate an A4-sized page filled with 16x16 grey ellipses
$ ./sample_balls --size a4 --balls-per-row 16 --mode grey > test_a4_grey.svg

# Generate a US Letter-sized page filled with 2x2 gradient-filled ellipses
$ ./sample_balls --size letter --mode bw-radial-gradient > test_letter_grads.svg
```

Pages with a few grey ellipses are simple and therefore easy to process, while
pages filled with thousands of radial gradient-filled ellipses pose a formidable
challenge at larger sizes and higher resolutions.

Have fun!

## Licensing
Licensing terms may vary between files in this repository, as it may contain
copy-pasted material licensed by other authors.

Please check individual files for licensing terms and conditions, if you wish to
use any code or information in this repository in your own work.

## Links
If you are looking for the libre open-source CAPT driver:

* [Alexey Galakhov's original captdriver repository](https://github.com/agalakhov/captdriver)

  * [My version](https://github.com/mounaiban/captdriver)

Other stuff:

* The [unofficial Captdriver Wiki!](https://github.com/mounaiban/captdriver/wiki)

* Alexey's CAPT [reverse-engineering "scratch repo"](https://github.com/agalakhov/anticapt)

