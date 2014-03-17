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

# Wait some seconds and then change setting, define evb22.enableTx=no
sleep 30;
$1/lldptool -i veth0 -gncb -T -V evb -c enableTx=no
rc=$?
if [ $rc -ne 0 ]
then
	echo $rc "FAILURE:lldptool -i veth0 -gncb -T -V evb -c enabletx=no"
	exit $rc
fi

sleep 20
$1/lldptool -i veth0 -gncb -T -V evbcfg -c enableTx=no
rc=$?
if [ $rc -ne 0 ]
then
	echo $rc "FAILURE:lldptool -i veth0 -gncb -T -V evbcfg -c enabletx=no"
	exit $rc
fi

sleep 10
lines="$(fgrep 'enableTx = false;' /tmp/$(basename $0 .sh)-lldpad.conf | wc -l)"

if [ "x$lines" != x2 ]
then
	rc=5
	echo $rc "FAILURE:lldptool -V evbcfg/evb -c enabletx=no"
fi
exit $rc
