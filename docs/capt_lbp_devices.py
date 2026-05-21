"""
Code to Generate Formatted Lists of CAPT Devices
------------------------------------------------
by Moses Chong

Requires CAPT devices data source "capt-lbp-devices.json".

This Python module contains code to programatically generate
and verify formatted lists of CAPT devices from the data source
for use in other programs and in documents.

License
=======
Creative Commons CC-BY-SA 4.0

Device List Format Description
==============================
Device list source file to be stored in JSON (CSV also acceptable)
Columns from left to right are:

USB Product ID, Model Name, Features, URL

Features can be zero or more of the following:
* C full colour,
* D duplex/two-sided printing (optional or built-in),
* N network card support (optional or built-in),
* S uses CAPT 1.x with SCoA (run-length + delta coding),
* T paper tray expansion support,
* 3 A3-size (and similar) media support

An empty feature set implies:
* monochrome printing
* Hi-SCoA compression (LZ77 + Elias universal-style coding /w pushdown automation arch.)
* CAPT 2.0 or later communications protocol
* No networking
* No two-sided printing
* No support for add-in paper trays
* A4 or slightly larger max paper size

All devices on the list have a USB Vendor ID of 0x04a9.
All CAPT 2.x devices are network-capable; devices without a network card
port could use optional Canon-endorsed, CAPT-compatible USB dongles supplied
by Axis Communications.

Device List Preparation
=======================
The device list source file was prepared by running the following
commands in this order:

curl https://usb-ids.gowdy.us/usb.ids > usb.ids.txt
cat usb.ids.txt | grep LBP | sed -e s/^\\t/\[\"/ | sed -e s/\ \ /\"\,\"\/ | sed -e s/$/\"\,\"\"\,\"\"\]\,/

Some manual formatting was done to make the formatting more
ECMA-404 compliant, and to add LBP5200 to the list.

"""

from json import JSONDecoder
from itertools import chain

src = "capt-lbp-devices.json"
jd = JSONDecoder()

def get_dev_list(path):
    """Read JSON source file into a Python list"""
    out = []
    with(open(path, mode='r') as f):
        out = jd.decode(f.read())
    return out

def c_lookup(dev_list):
    """Output Struct Array for usb_a1a1.c"""
    rows = ("    {{0x{}, \"{}\"}},\n".format(x[0], x[1]) for x in dev_list)
    out = chain("{\n", rows, "};")
    return ''.join(out)

def md_table(dev_list):
    """Output Markdown Table for Device List"""
    columns = ("Model", "USB Product ID", "Features")
    feat_pics = {
        ord('C') : "🔵🟣🟡",
        ord('D') : "🔃",
        ord('N') : "⚡",
        ord('S') : "🔺",
        ord('T') : "📤",
        ord('3') : "📄",
    }
    head = "|".join(columns)
    rule = "|{}\n".format("--|"*len(columns))
    sorted_list = sorted(dev_list, key=lambda x:x[1])
        # sort by Model, not USB ProdID
    body = ("[{}]({})|{}|{}\n".format(x[1], x[3], x[0], x[2].translate(feat_pics)) for x in sorted_list)
        # pay attention...
    return ''.join(chain(head, '\n', rule, body))

def usb_a1a1_test_cmd(ex_name, dev_list):
    """Output test command for usb_a1a1.c"""
    vid_canon = "04a9"
    usb_ids = ''.join(" {}{}".format(vid_canon, x[0]) for x in dev_list)
    out = "for i in{}; do {} --test $i; done;".format(usb_ids, ex_name)
    return out
