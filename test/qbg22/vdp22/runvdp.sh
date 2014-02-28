#!/bin/bash
#
# Execute test case for LLDPAD testing according to IEEE 802.1Qbg
#
# Copyright (c) International Business Machines Corp., 2013
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
# Execute a single test. Parameter is the name of the test file.
# Run 2 lldpad instances in parallel using 2 network name spaces
#

# Check if lldpad (bridge role) is up and running. Do not use the pid file.
# Return 0 is not running and 1 if running (pid returned as string)
function lldpad_brpid()
{
	PID_lldpbr=$(ps -ef | fgrep lldpad | fgrep -- .vdp | awk '{ print $2 }')
	if [ -z "$PID_lldpbr" ]
	then
		return 0
	fi
	return 1
}

# Check if lldpad is up and running. Return pid or 0 if not running.
function lldpad_pid()
{
	PID_lldp=$(ps -ef | fgrep lldpad | fgrep -- .conf | awk '{ print $2 }')
	if [ -z "$PID_lldp" ]
	then
		return 0
	fi
	return 1
}

function lldpad_stop()
{
	if [ "$1" -eq 0 ]
	then
		echo "$0:lldpad $2 terminated unexpectedly"
		return 1
	fi
	kill -s SIGTERM $1
	sleep 1
	ps -p $1 -o pid --no-header > /dev/null
	if [ $? -ne 1 ]
	then
		kill -s SIGKILL $1
	fi
	return 0
}

function cp_include()
{
	for i in $(fgrep @include $1 | awk '{ print $2 }' | sed 's-"--gp')
	do
		cp $i /tmp
	done
}

# Use the correct lldpad configuration file and start lldpad.
# Parameter 1: path to lldpad to use
# Parameter 2: name of configuration file
function lldpad_start()
{
	if lldpad_pid
	then
		rm -f /var/lib/lldpad/lldpad.conf ./lldpad.conf
		cp $2 /tmp/$2
		$1/lldpad -V7 -f /tmp/$2 >/tmp/$2.out 2>&1 &
		sleep 1
		if lldpad_pid
		then
			echo "$0:lldpad not started or terminated unexpectedly"
			exit 1
		else
			echo "LLDPAD running pid $PID_lldp"
		fi
	else
		exit 1
	fi
	return 0
}

# Start lldpad in bridge role
# Testfile is an lldpad configuration file with bridge settings.
# Run lldpad without creating the /var/run/lldpad.pid file
function lldpad_brstart()
{
	if lldpad_brpid
	then
		cp $2 /tmp/$2
		cp_include $2
		cmd="./ns_unshare -i -- ../../../lldpad -p -V7 -f /tmp/$2"
		ip netns exec bridge_ns $cmd > /tmp/$2.out 2>&1 &
		sleep 1
		if lldpad_brpid
		then
			echo "$0:lldpad bridge role not started or terminated unexpectedly"
			return 1
		else
			echo "LLDPAD bridge role running pid $PID_lldpbr"
		fi
	else
		return 1
	fi
	return 0
}

if ! ip netns list | fgrep -qi bridge_ns
then
	echo "$0:bridge_ns network name space missing"
	exit 1
fi

if ! which runvdp.sh 1>/dev/null 2>/dev/null
then
	export PATH=$PATH:$PWD
fi

# Extract type of test case from last 3 characters of invocation
type=$(basename $0)
type=".${type:3:3}"

testfile=$1
no=$(basename $testfile $type)

# Find out if test case file is a lldpad configuration file to run lldpad
# in bridge mode
if ! egrep -qi tlvid0080c20d $testfile && egrep -qi 'evbmode[ \t]*=[ \t]*"?bridge"?' $testfile
then 
	echo "$0:use qbg22sim as bridge simulator"
	exit 1
fi

# Start lldpad using this name space
if ! lldpad_start ../../.. $no-lldpad.conf
then
	echo "$0:can not start lldpad"
	exit 1
fi

# Start lldpad bridge role
if ! lldpad_brstart ../../.. $no.vdp
then
	echo "$0:can not start lldpad in bridge role"
	# Stop lldpad
	lldpad_stop $PID_lldp "station role"
	exit 1
fi

# Check for shell script to run in parallel
if [ -r "./$no.sh" -a -x "./$no.sh" ]
then
	./$no.sh ../../.. &
fi

# Start vdptest test program
if [ -r "$no.nlc" ]
then
	./$no.nlc >/tmp/$no.nlc.out 2>&1
	rc=$?
fi

# Stop lldpad
lldpad_stop $PID_lldpbr "bridge role"
lldpad_stop $PID_lldp "station role"

exit $rc
