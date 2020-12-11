# studycapt
Welcome to the Studies In Implementing Support for CAPT Printers!

This is just a repository for miscellaneous experiments, tools and tips dedicated
to an ongoing goal of implementing a *superior*® alternative driver for CAPT-only
Canon laser printers.

For now, there's just ``find_msb.py``, an experiment in trying to improve
``find_msb()``. It contains benchmarks and re-implementations of the function,
examined in Python.

### Running the Benchmarks
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
