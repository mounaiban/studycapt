# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips dedicated
to an ongoing goal of implementing a *superior*® alternative driver for CAPT-only
Canon laser printers.

For now, there's just two items:

* ``find_msb.py``, an experiment in trying to improve ``find_msb()``

* ``bytes2pbm``, a command line tool to generate 1-bit Portable Bitmaps
  (specifically, PBM P1 images). Includes an importable function, ``bytes_to_pbm()``

### Running the find\_msb() Benchmarks
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

### Using bytes2pbm
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
