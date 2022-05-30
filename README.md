# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips
dedicated to an ongoing goal of implementing a *superior*<sup>®</sup>
alternative driver for CAPT-only Canon laser printers.

Here's a rundown on what's in here:

### [docs](docs) (Docs and Notes)
First and foremost, this is the place for study notes documenting research
on CAPT printers, improvement of captdriver, test procedures and other
miscellaneous information.

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

### [in2pbmp4.sh](in2pbmp4.sh) (Input to PBM P4 Image Script)
A script originally created to help visualise arbitrary data as a PBM P4
image. Currently obsolete and due for an improvement. For now a `printf`
and a `dd` is probably more usable:

```sh
# Example for 200x200 1bpp image
printf "P4\n200 200\n" > example.pbm
dd if=input.bin bs=$((200 * 200 / 8)) count=1 >> example.pbm   # PROTIP: '>>' for appending, NOT '>'
```

The format is like:
```sh 
printf "P4\n200 200\n" > $OUTPUT_FILE
dd if=$INPUT_FILE bs=$((200 * 200 / 8)) count=1 >> $OUTPUT_FILE
```

Try `/dev/urandom` as an input file for a start!

### [sample\_balls.py](sample_balls.py) (Performance Test Page Generator)
A Python script to generate test pages of varying complexity in SVG format, in
order to test rasteriser and compressor performance.

```bash
# Generate an A4-sized page filled with 16x16 grey ellipses
$ ./sample_balls.py --size a4 --balls-per-row 16 --mode grey > test_a4_grey.svg

# Generate a US Letter-sized page filled with 2x2 gradient-filled ellipses
$ ./sample_balls.py --size letter --mode bw-radial-gradient > test_letter_grads.svg
```

Run `./sample_balls.py --help` for a list of options.

Pages with a few grey ellipses are simple and therefore easy to process, while
pages filled with thousands of radial gradient-filled ellipses pose a formidable
challenge at larger sizes and higher resolutions.

### [sample\_blots.py](sample_blots.py) (RLE Test Page Generator)
A Python script to generate images for analysis of RLE algorthms. This script was
originally created to study the Smart Compression Architecture (SCoA) algorithm
used by select late-1990s and early-2000s Canon laser printers. It may be used
for analysing other RLE codecs as well.

PBM P4 and PGM P5 output formats are supported.

```bash
# Generate a 1-bit, 600dpi A4-sized image with pixel runs of different length
$ ./sample_blots.py --mode mirrored-incr-runs --size=a4 --resolution 600 --format p4 --out_file test.pbm

# Alternative example using stdout
# (WARNING: ordinary files will be overwritten without warning)
$ ./sample_blots.py --mode mirrored-incr-runs --size=a4 --resolution 600 --format p4 > test.pbm
```

Run `./sample_blots.py --help` for a list of options.

### [scoa.py](scoa.py) (SCoA Toolkit)
A Python module containing a SCoA decompressor among other utilities for
decompressing SCoA images or print data. The decompressor should work,
but has not yet been thoroughly validated.

See also [Issue #33](https://github.com/agalakhov/captdriver/issues/33)
on the original captdriver repo for details.

```python
from scoa import SCoADecoder

# Create a decoder object for a 596-byte wide bitmap
decoder = SCoADecoder(596)
```

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

