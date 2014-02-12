#!/bin/bash
#
# Test case for LLDPAD ECP Testing according to IEEE 802.1Qbg
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
# Thomas Richter, IBM Research & Development, Boeblingen, Germany, 16-Nov-2012
#
# Execute a single task on the machine running lldpad
#

# Wait 30 seconds and disable/enable interface
sleep 30;
ip l s down dev veth0
sleep 10
ip l s up dev veth0
ip a sh dev veth0 | fgrep -q UP
exit $?

