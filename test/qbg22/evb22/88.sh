#!/bin/bash
#
# Test case for LLDPAD EVB Testing according to IEEE 802.1Qbg
#
# Copyright (c) International Business Machines Corp., 2014
#
# Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#
# Configuration file for unknwon vsi data test cases
#

#
# Thomas Richter, IBM Research & Development, Boeblingen, Germany, 16-Aug-2012
#
# Execute a single task on the machine running lldpad
#

# Wait 50 seconds before executing command
sleep 50;

$1/lldptool -i veth0 -gncb -T -V evb -c vdprwd=31
rc=$?
if [ "$rc" -ne 0 ]
then
	let rc=98
	echo $rc "FAILURE:lldptool -i veth0 -gncb -T -V evb -c vdprwd=31"
	exit $rc
fi

sleep 3

out=$($1/lldptool -i veth0 -gncb -t -V evb -c vdprwd)
rc=$?
if [ "$rc" -eq 0 ]
then
	# echo out ":$out:"
	if [ "$out" != "vdprwd=31" ]
	then
		rc=99
	fi
fi
# First field contains exit code of shell script, 0 for success anything else
# for failure.
echo $rc ":$out:"
exit $rc
