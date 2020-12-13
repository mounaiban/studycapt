#! /bin/sh
#
# in2pbmp4.sh - Any Input to PBM P4 Image
# Create a PBM P4 image out of a file for quick and dirty
# visualisation of binary data
#
# by Moses Chong 
# (2020/12/13)
#
# Usage: in2pbmp4 width height input_file > output_file
# Example: in2pbmp4 80 80 in_file.bin > out_file.pbm
# 
# For best results, make sure width * height is a multiple of 8.
# Excess bytes will not be used in the image.
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software
# to the public domain worldwide. This software is distributed
# without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication
# along with this software. If not, see:
# <http://creativecommons.org/publicdomain/zero/1.0/>. 
#
if test $# == 3; then echo -e "P4\n$1 $2\n" && dd ibs=$((($1 * $2) / 8)) count=1 if=$3 conv=block status=none; else echo "Usage: $0 w h input_file > output_file" ; fi

