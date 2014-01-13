/*******************************************************************************

  Implementation of VDP 22 (ratified standard) according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2014

  Author(s): Thomas Richter <tmricht@linux.vnet.ibm.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

/*
 * Command interface for vdp22 module.
 */

#ifndef QBG_VDP22_CMDS_H
#define QBG_VDP22_CMDS_H

struct arg_handlers *vdp22_arg_handlers();
int vdp22_clif_cmd(void *, struct sockaddr_un *, socklen_t, char *, int, char *,
		   int);
#define VAL_STATION		"station"
#define VAL_BRIDGE		"bridge"
#define ARG_VDP22_VSI		"vsi"

#endif
