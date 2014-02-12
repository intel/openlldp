#!/bin/bash
#
# Execute test case for LLDPAD testing according to IEEE 802.1Qbg
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

#
# Thomas Richter, IBM Research & Development, Boeblingen, Germany, 16-Aug-2012
#
# Execute a single  test. Parameter is the name of the test file
#

# Check if lldpad is up and running. Return pid or 0 if not running.
# Note that lldpad may be started without creating a PID file. If no PID file
# exists, use the lldptool to query the PID of lldpad.
function lldpad_up()
{
	if [ ! -r /var/run/lldpad.pid ]
	then
		pidfile=$(../../../lldptool -p 2>/dev/null)
		if [ "$?" -ne 0 ]
		then
			return 0
		fi
	else
		pidfile="$(cat /var/run/lldpad.pid)"
	fi
	if [ -z "$pidfile" ]
	then
		return 0
	else
		ps -p $pidfile -o pid --no-header > /dev/null
		if [ $? -ne 0 ]
		then
			return 0
		fi
	fi
	echo "LLDPAD running pid $pidfile"
	return $pidfile
}

function lldpad_down()
{
	if [ ! -r /var/run/lldpad.pid ]
	then
		pidfile=$(../../../lldptool -p 2>/dev/null)
		if [ "$?" -ne 0 ]
		then
			return 1
		fi
	else
		pidfile="$(cat /var/run/lldpad.pid)"
	fi
	if [ -z "$pidfile" ]
	then
		return 1
	fi
	kill -s SIGTERM $pidfile
	sleep 1
	ps -p $pidfile -o pid --no-header > /dev/null
	if [ $? -ne 1 ]
	then
		kill -s SIGKILL $pidfile
	fi
	return 0
}

# Use the correct lldpad configuration file and start lldpad.
# Parameter 1: path to lldpad to use
# Parameter 2: name of configuration file
function lldpad_start()
{
	if lldpad_up
	then
		rm -f /var/lib/lldpad/lldpad.conf ./lldpad.conf
		cp $2 /tmp/$2
		$1/lldpad -V7 -f /tmp/$2 >/tmp/$2.out 2>&1 &
		sleep 1
		if lldpad_up
		then
			echo "$0:lldpad not started or terminated unexpectedly"
			exit 1
		fi
	else
		exit 1
	fi
	return 0
}

if ! which runevb.sh 1>/dev/null 2>/dev/null
then
	export PATH=$PATH:$PWD
fi

# Extract type of test case from last 3 characters of invocation
type=$(basename $0)
type=".${type:3:3}"

testfile=$1
no=$(basename $testfile $type)

# Start lldpad using this name space
if ! lldpad_start ../../.. $no-lldpad.conf
then
	echo "$0:can not start lldpad"
	exit 1
fi

# Check for shell script to run in parallel
if [ -r "./$no.sh" -a -x "./$no.sh" ]
then
	./$no.sh ../../.. > /tmp/$no.sh.out &
fi

# get the duration from the last entry in the test file.
duration=$(cpp $testfile | cut -f1 -d' ' | sed '/^$/d' | tail -1)
let duration=duration+5

# run the test with output save to /tmp/testfile.out
ip netns exec bridge_ns ../../../qbg22sim -v -v -v -T 5000000 -d $duration veth2 $testfile > /tmp/$testfile.out
rc=$?

# Stop lldpad
if ! lldpad_down
then
	echo "$0:can not stop lldpad"
	exit 1
fi

# Check for output file script to test result of test case
if [ -r "/tmp/$no.sh.out" ]
then
	rc=$(cut -f1 -d' ' "/tmp/$no.sh.out")
fi

exit $rc
