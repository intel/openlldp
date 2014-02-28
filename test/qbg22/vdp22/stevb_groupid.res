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
# Thomas Richter, IBM Research & Development, Boeblingen, Germany, 11-Jul-2013
#
# LLDPAD station mode default resource file
#
tlvid0080c20d : 
{
	enableTx = true;
	evbmode = "station";
	evbrrcap = true;
	evbrrreq = true;
	evbgpid = true;
	ecpretries = 3;
	ecprte = 14;
	vdprwd = 20;
	vdprka = 20;
};
