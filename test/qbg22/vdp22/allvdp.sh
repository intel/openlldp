#!/bin/bash
#
# Test case for LLDPAD VDP Testing according to IEEE 802.1Qbg
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
# Thomas Richter, IBM Research & Development, Boeblingen, Germany, 16-Aug-2013
#
# Execute the complete vdp test suite.
#

runcommand()
{
	# echo parameter $@
	cmd=$1
	file=$2

	echo "start testcase $number"
	$cmd $file 2>&1
	rc="$?"
	if [ "$rc" -ne 0 ]
	then
		echo -en "\\033[1;31m"	# Failures in red
		echo "ERROR $file exit with $rc"
		echo -en "\\033[0;39m"
		exit 2
	fi
	echo -en "\\033[1;32m"	# Success in green
	echo "OK testcase $file"
	echo -en "\\033[0;39m"
	return 0
}

# Extract type of test case from the first 3 characters of invocation file
type=$(basename $0)
type="${type:3:3}"

if ! which run$type.sh 2>/dev/null
then
	export PATH=$PATH:.
fi

echo "Start testsuite at $(date)"
for i in $(ls [1-9]*.$type|sort -n)
do
	runcommand run$type.sh $i
done
echo "Stop testsuite at $(date)"
exit 0
