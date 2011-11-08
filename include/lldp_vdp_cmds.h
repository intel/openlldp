/*******************************************************************************

  implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2010

  Author(s): Jens Osterkamp <jens@linux.vnet.ibm.com>

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

#ifndef _LLDP_VDP_CMDS_H
#define _LLDP_VDP_CMDS_H

struct arg_handlers *vdp_get_arg_handlers();
char *print_profile(char *, size_t, struct vsi_profile *);

enum {
       MODE = 0,
       MGRID,
       TYPEID,
       TYPEIDVERSION,
       INSTANCEID,
       FORMAT,
};

#define VAL_STATION    "station"
#define VAL_BRIDGE     "bridge"

#endif
