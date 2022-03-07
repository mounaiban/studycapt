# Mounaiban/Captdriver Issue #10 Test PDF

This document was created for [Issue #10](https://github.com/mounaiban/captdriver/issues/10)
to discover more about the LBP7200Cdn, in pursuit of adding support
for this printer device to Captdriver.

## Reproducing the Test PDF

The PDF may be reproduced as follows on a UNIX-compatible shell with
the following list of commands while inside a directory containing
`sample_balls.py`:

> *WARNING*: Ensure that there are no files with names starting with
> `issue-10` in your destination directory to avoid accidentally
> overwriting files.

```sh
# rsvg-convert is used in this example, install either librsvg2-bin
# (APT) or the librsvg-tools (YUM/DNF) packages, or equivalent.
#
PZ=a4               # change this to use a different page size
DOCS=~/Documents    # change this as appropriate
./sample_balls.py --size=$PZ --mode=color --balls-per-row=4 > $DOCS/issue-10-svg-1.svg
./sample_balls.py --size=$PZ --mode=color-radial-gradient --balls-per-row=2 > $DOCS/issue-10-svg-2.svg
./sample_balls.py --size=$PZ --mode=bw-radial-gradient --balls-per-row=2 > $DOCS/issue-10-svg-3.svg
./sample_balls.py --size=$PZ --mode=black --balls-per-row=4 > $DOCS/issue-10-svg-4.svg
./sample_balls.py --size=$PZ --mode=grey --balls-per-row=4 > $DOCS/issue-10-svg-5.svg
cd $DOCDIR
rsvg-convert -f pdf -o issue-10.pdf issue-10-svg-1.svg issue-10-svg-2.svg issue-10-svg-3.svg issue-10-svg-4.svg issue-10-svg-5.svg issue-10-svg-5.svg issue-10-svg-5.svg issue-10-svg-5.svg
```

Please note that `issue-10-svg-5.svg` is repeated four times in a row in the
`rsvg-convert` command.

## Troubleshooting

If you have ``rsvg-convert`` version 2.40.2, use this as the last command
instead in order to work around a scaling bug:

```sh
rsvg-convert -f pdf -x 0.801 -y 0.801 -o issue-10.pdf issue-10-svg-1.svg issue-10-svg-2.svg issue-10-svg-3.svg issue-10-svg-4.svg issue-10-svg-5.svg issue-10-svg-5.svg issue-10-svg-5.svg issue-10-svg-5.svg
```

On some systems, you might have to put `python3` before `./sample_balls.py`
to work around a "bad interpreter" error.

