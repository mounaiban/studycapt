# Captdriver Manual Performance Test Procedure v0.1.5

This is a definition for a standard, reproducible test for diagnosing the issue
causing delays between pages on captdriver.

## Prerequisites

The following software are required for this test:

* `rsvg-convert`

	* APT package: `librsvg2-bin`  (for Debian, Ubuntu or APT-based distros)

    * DNF package: `librsvg-tools` (for Fedora or DNF-based distros)

    * verify installation with `rsvg-convert -v`

* `sample_balls.py` from this repository

## Note on test consistency and accuracy

As print performance varies widely between systems, configurations and ambient
temperature, these tests are relative and intended only to detect and confirm
improvements and regressions.
  
### Preparation

Prepare the sample pages:

```sh
# This example prepare A4-sized pages
#
# Please check $HOME/Documents for actual files named p1.svg, p2.svg, etc...
# as these WILL be overwritten. Change file names and directories as needed.

PZ=a4
DOCS=$HOME/Documents
./sample_balls.py --size=$PZ --balls-per-row=2 --mode=gray > $DOCS/p1.svg
./sample_balls.py --size=$PZ --balls-per-row=64 --mode=bw-radial-gradient > $DOCS/p2.svg
./sample_balls --size=$PZ --balls-per-row=4 --mode=gray > $DOCS/p3.svg

# Optional color page
./sample_balls --size=$PZ --balls-per-row=4 --mode=color > $DOCS/p4.svg
```

Combine the samples into a single PDF:
```sh
cd $DOCS
rsvg-convert -f pdf -o captperftest.pdf p1.svg p2.svg p3.svg
# add p4.svg at the end of the command to include optional page 
```

#### Test page description
The first page contains a 'simple' layout that is expected to be processed
quickly.

The second page contains a 'complex' layout that is designed to provoke delays
in job processing and to increase the overall amount of data to be handled by
the printer device.

The third page is another simple layout like the first page. It meant to be
processed quickly, but it also serves to troubleshoot delays between pages.

The optional fourth page contains colour objects that is intended to test colour
output on capable devices.

#### Miscellaneous notes

Size names and other options are in lowercase only unless stated otherwise.

If you get a `bad interpreter` error, you may have to run
`python3 sample_balls.py` instead of just `./sample_balls.py`

### Execution: Printing from a PDF viewer

Open the test document ``captperftest.pdf`` prepared earlier, and print with
a device supported by captdriver. Any application would do, but Mozilla Firefox
is the default for this project.

* Using a multi-lap stopwatch (like most digital stopwatches or apps), measure
  the time it takes for the entire job to complete from the moment the Print
  button in the PDF viewer is pressed.
  
* Set a new lap time the moment a page completely lands on the output tray.

