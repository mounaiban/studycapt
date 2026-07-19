# Smart Compression Architecture (SCoA) Specifications
This document is about the raster codec used by select Canon laser printers, using the CAPT protocols, made between the late-1990s to the mid-2000s.

For information on the distinct Hi-SCoA codec on later CAPT printers made from the mid-2000s to the early-2010s, please see part 1.4 and 3 of the [SPECS](https://github.com/agalakhov/captdriver/blob/master/SPECS) file in the tree.

# Overview
SCoA (expanded to _Smart Compression Architecture_ in some marketing materials) is a lossless[^lossless] compression codec for 1-bit (bi-level) monochrome images which makes use of [Run-Length Encoding](https://en.wiktionary.org/wiki/run-length_encoding#English) (RLE) and [Delta Encoding](https://en.wikipedia.org/wiki/Delta_encoding).

Images begin with a "key" or "seed" line. Pixels on each line are processed at the byte level, each byte representing eight 1-bit pixels (like [Netpbm P4](https://netpbm.sourceforge.net/doc/pbm.html)). The first key line is taken from the first line of the image, and is run length encoded; contiguous repeated bytes are replaced by a single byte with a repeat count.

Delta encoding is applied on lines following the key line. The delta encoding is applied to the uncompressed line, *not* its RLE form. Bytes that are repeated from previous line are reduced to a single reference with the number of bytes to copy. Bytes that are different from the previous line are run-length encoded.

Lines can be ended early with an End-of-Line (EOL) opcode that fills the rest of the line with bytes copied from the previous line. Whole lines can be repeated with a lone EOL opcode.

An image can contain multiple key lines if necessary, but a single key line is sufficient to encode the average document.

The compressed stream is terminated with an End-of-Page opcode. Unlike lines, pages cannot end early. All lines on a page must be encoded. If the content on a page doesn't reach the bottom, or if the page is a blank page, the blank space must be filled by a key line followed by a series of EOL opcodes.

No SCoA colour devices are known to exist. Canon has claimed that full colour support was only introduced with the newer and distinct Hi-SCoA codec in product brochures for the LBP2410.

[^lossless]: SCoA is lossless at the *raster* level. All loss of information or fidelity during conversion to a printable format occur during the rasterisation process. There is no loss of detail from the final raster.

# Opcodes

> Note: The SCoA format is not yet completely charted. Information in this section may be subject to change.

## Syntax
SCoA uses a variable-length encoding system with interleaved opcodes and arguments, resulting in a byte-aligned code.
Codes are read in **big-endian order**.

### Data Opcodes
These opcodes store data in a compressed form. Opcodes are composed of an *operation*, and *arguments* (or operands). Arguments may be counts or literals. Counts determine the number of repetitions, or the length of an uncompressed string of literals, while literals are written to the output stream.

Operations and counts are interleaved and packed in the first bytes of the opcode and are always followed by literals. **All counts are unsigned integers**.

#### Example of Operation and Counts in One byte

`0b00XXXYYY` `S0..Sn`

* Operation: `0b00`
* Count X: `0bXXX` 
* Count Y: `0bYYY`
* Literals: string `S0` to `Sn`

#### Examples of Operation and Counts in Two bytes

`0b100WWWWW` `0b00YYYXXX` `S0..Sn`

* Operation `0b10000`
* Count W+X: `0bWWWWWXXX`
* Count Y: `0bYYY`
* Literals: string `S0` to `Sn`

`0b101WWWWW` `0b00YYYXXX` `C`

* Operation `0b10100`
* Count W+X: `0bWWWWWXXX`
* Count Y: `0bYYY`
* Literal: `C`

#### Example of Operation and Counts in Three bytes

`0b100UUUUU` `0b101WWWWW` `0b11XXXYYY` `C`

* Operation: `0b10010111`
* Count U+Y: `0bUUUUUYYY`
* Count W+X: `0bWWWWWXXX`
* Literal: `C`

### Control Opcodes
Control opcodes affect the decompressor's behaviour and are shown in base-16 (`0x`). These commands have no counts and cannot be compressed (although having a compressible EOL would have further increased efficiency).

## Operations

There are three data decoding operations:
* `copy(n)`: Copy `n` bytes from the previous line, at the same offset/position as the current line
* `repeat(n, C)`: Repeat, `n` times, the single byte `C`
* `raw(n, S0...Sn)`: Write `n` new uncompressed bytes `S0` to `Sn`.

The `+` operator herein concatenates the results of the operations.

| Opcode | Operation | Canonical Name (TBC) | Description |
|--|--|--|--|
| `0b00YYYXXX` `S0..Sn` | `copy(0bXXX) + raw(0bYYY, S0..Sn)` | `CopyThenRaw` | `0bXXX` (0-7) bytes from previous line then `0bYYY` (1-7) uncompressed bytes `S0` to `Sn` |
| `0b01YYYXXX` `C` | `copy(0bXXX) + repeat(0bYYY, C)` | `CopyThenRepeat` | `0bXXX` (0-7) bytes from previous line then `0bYYY` (1?-7) repeats of `C` <br>Note: (minimum `repeat()` count may be 2, not 1; please see [this comment](https://github.com/agalakhov/captdriver/issues/33#issuecomment-1874751389) in #33 in the original repo)|
| `0b11XXXYYY` `C` `S0..Sn` | `repeat(0bXXX, C) + raw(0bYYY, S0..Sn)` | `RepeatThenRaw` | `0bXXX` (1-7) repeats or `C`, then `0bYYY` (1-7) uncompressed bytes `S0` to `Sn`. |
| `0b11000YYY` | `copy(0bYYY)` | `?` | `0bYYY` (1-7) bytes from the previous line only. Identical to `RepeatThenRaw` with one zero count |
| `0b11XXX000` | `copy(0bXXX)` | `?` | `0bXXX` (1-7) bytes from the previous line only. Identical to `RepeatThenRaw` with one zero count |
| `0b100WWWWW` `0b00YYYXXX` `S0..Sn` | `copy(0bWWWWXXX) + raw(0bYYY, S0..Sn)` | `CopyThenRawLong` | `0bWWWWWXXX` (8-255) bytes from previous line, then `0bYYY` (1-7) uncompressed bytes `S0` to `Sn`. |
| `0b100WWWWW` `0b01YYYXXX` `C` | `copy(0bWWWWXXX) + repeat(0bYYY, C)` | `CopyThenRepeatLong` | `0bWWWWWXXX` (8-255) bytes from previous line, then `0bYYY` (1-7) repeats of `C`. |
| `0b100WWWWW` `0b11000XXX` | `copy(0bWWWWXXX)` | `?` | `0bWWWWWXXX` (8-255) bytes from the previous line only |
| `0b100WWWWW` `0b11YYY000` | `copy(0bWWWWYYY)` | `?` | `0bWWWWWYYY` (8-255) bytes from the previous line only |
| `0b101WWWWW` `0b00XXXYYY` `C` `S0..Sn` | `repeat(0bWWWWXXX, C) + raw(0bYYY, S0..Sn)` | `RepeatThenRawLong` | `0bWWWWWXXX` (8-255) repeats of `C`, then `0bYYY` (1-7) uncompressed bytes `S0` to `Sn` |
| `0b101XXXXX` `0b01WWWYYY` `C` `S0..Sn` | `repeat(0bWWW, C) + raw(0bXXXXXYYY, S0..Sn)` | `RepeatThenRawLong` | `0bWWW` (1-7) repeats of `C`, then `0bXXXXXYYY` (8-255) uncompressed bytes `S0` to `Sn`. |
| `0b101XXXXX` `0b10YYYWWW` `C`| `copy(0bWWW) + repeat(0bXXXXXYYY, C)` | `CopyThenRepeatLong` | `0bWWW` (0-7) bytes from the previous line, then `0bXXXXXYYY` (8-255) repeats of `C` |
| `0b101XXXXX` `0b11YYYWWW` `S0..Sn` | `copy(0bWWW) + raw(0bXXXXXYYY, S0..Sn)` | `CopyThenRawLong` | `0bWWW` (0-7) bytes from the previous line, then `0bXXXXXYYY` (8-255) uncompressed bytes `S0` to `Sn` |
| `0b100UUUUU` `0b101XXXXX` `0b10YYYWWW` `C` | `copy(0bUUUUUWWW) + repeat(0bXXXXXYYY, C)` | `CopyThenRepeatLong` | `0bUUUUUWWW` (8-255) bytes from previous line, then `0bXXXXXYYY` (8-255) repeats of `C`. |
| `0b100UUUUU` `0b101XXXXX` `0b11YYYWWW` `S0..Sn` | `copy(0bUUUUUWWW) + raw(0bXXXXXYYY, S0..Sn)` | `CopyThenRawLong` | `0bUUUUUWWW` (8-255) bytes from previous line then `0bXXXXXYYY` (8-255) uncompressed bytes `S0` to `Sn`.  |
| `0x40` | `NOP` | `NOP` | Dummy non-op. |
| `0x41` | `EOL` | `EOL` | End of line. Fill the rest of the current line with bytes from the previous line from the same offset on the current line |
| `0x42` | `EOP` | `EOP` | End of page/picture. Don't decompress anything past this point. |
| `0x9f`/`0b10011111` | `n + 248` | `Extend` | Add 248 to the byte count for `copy()` in `copy()+raw()` and `copy()+repeat()` commands.<br>Can be used N times in a row for 248 * N bytes.<br>Identical to the first byte in `copy(n)+raw(m, S0..Sm)` and `copy(n)+repeat(m, C)` where `n` is from 248 to 255. |

The list of operations is believed to be largely complete at time of writing.

## Transmission
Encoded images are sent to the printer inside `IC_VIDEO_DATA` (`0xC0A0`) packets when the printer device is connected via USB or TCP/IP/Ethernet.

## Notes

### Opcode Names
Canonical names were taken from a [disassembly of the `captfilter` command](https://github.com/agalakhov/captdriver/issues/33#issuecomment-1098299951) from the original Canon driver. `Copy` is currently understood as "copy from previous line", and `Raw` is currently understood as "uncompressed".

### Tracking the Previous Line
The decoder should keep track of the position on the previous line. Every operation advances the position by its count, regardless of using the contents of the previous line or not. For example:

`copy(7) + raw(2, [0xBA, 0xBE]) + copy(7) + repeat(17, 0xCC) + copy(7)`

Copies 7 bytes from the previous line,

Skips the next 2 bytes and inserts `[0xBA, 0xBE]` instead,

Copies another 7 from the previous line,

Skips the next 17 and inserts the same amount of `0xCC` bytes instead, and finally,

Copies yet another 7 from the previous line.

The behaviour of using `copy()` on the first line is unknown. As such, it is advised to assume an imaginary "previous line" entirely of zero `(0x00)` bytes before the first line on the compressed image.

### Extending `copy()` Byte Count With the 0x9f Opcode
The `copy()` in `copy()+raw()` and `copy()+repeat()` may be extended beyond 255 bytes by using one or more `0x9f` commands at the start of the opcode. For example, `0x9f` `0b10000001` `0b01010010` `C` dumps 258 bytes from the previous line followed by two repeats of `C`. Likewise, `0x9f` `0x9f` `0b10000001` `0b01010010` `C` does the same with 506 bytes. Only two `0x9f`'s are necessary to reach the end of the line on an 8.5 inch wide page at 600 dpi.

### Unknown Cases
It is yet to be known how `captfilter` or printers handle the following:

* Data that run *past* the end of line. `captfilter`'s encoder is careful to keep lines shorter than the line size. Should excess bytes be discarded or carried over to the next line?

* Input images with a width that is not a multiple of eight. Where should padding be added, or should the image be rejected outright?

* Output of `copy()` opcodes on the first line of the compressed image. What would printers output?

# Support
The libre open-source [captppd](https://github.com/darkvision77/captppd) driver supports printing to select SCoA printer devices.

# Decoder
An experimental working SCoA decoder is available from the [Studycapt](https://github.com/mounaiban/studycapt) repository. Instructions on its usage may be found in `README.md` of the source tree.

# References
Nicolas Boichat. LBP 810 and 1120 Driver [SPECS file](https://github.com/caxapyk/capt_lbp810-1120/blob/master/capt-0.1/SPECS). _Repository maintained by Alexander Sakharuk._

Canon (2003-12-01). Laser Shot LBP-2410 Colour Laser Printer. ICAN0275. SHA256: `250b5113a5986daf90ad2a44df683fa7afafb468a9635d4a8f1e86733b5d608b`

# Further Reading

**Issues [20](https://github.com/agalakhov/captdriver/issues/20) and [33](https://github.com/agalakhov/captdriver/issues/33)** on Alexey Galakhov's original captdriver repo contain historical discussions on supporting SCoA and CAPT 1.0 devices on contemporary operating systems.

**PackBits Compression**, described in detail in Section 9 of the [TIFF 6.0 Specification](https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.html) (1992-06-03). SCoA appears to have been influenced by PackBits, which similarly divides the data into uncompressed and compressed regions.

**pbm - Netpbm bi-level image format**. See [The Layout](http://netpbm.sourceforge.net/doc/pbm.html).

**Mode 9 Compression** as specified in Chapter 2 Section 6.3.8 of the [Brother Printer Technical Reference Guide](https://download.brother.com/welcome/doc002907/Tech_Manual_AD.pdf) implements similar delta coding techniques on Brother printers.
* Alternate download link: [Brother HL-2132 Manuals](https://support.brother.com/g/b/manualtop.aspx?c=au&lang=en&prod=hl2132_eu_as) (click on the Download link to the Command Reference Guide for Software Developers. The manual is also linked from information pages for most other laser printer products on the Brother website.

# Acknowledgements
This document is based on findings by Nicolas Boichat and documented in the source files of the [LBP810 and 1120 driver](https://www.boichat.ch/nicolas/capt/).

Thanks to [Alexey Galakhov](https://github.com/agalakhov) for explaining how captfilter and SCoA opcodes work, and [Oleg Sazonov](https://github.com/ra1nst0rm3d) for various tips, in the [SCoA Printers Support](https://github.com/agalakhov/captdriver/issues/33) issue in the original captdriver repo.

Thanks to [@ValdikSS](https://github.com/ValdikSS) and [Andrey Antufyev](https://github.com/darkvision77) for additional research and official Canon names for SCoA commands and CAPT packet types.

Thanks to [@deakjahn](https://github.com/deakjahn) for the tip on the copy-only operations in [Issue #3](https://github.com/mounaiban/studycapt/issues/3).
