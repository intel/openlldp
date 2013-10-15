/*******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2013

  Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>

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
 * External interface definition for the ratified standard VDP protocol.
 */
#ifndef QBG_VDP22DEF_H
#define QBG_VDP22DEF_H

/*
 * Define VDP22 filter formats.
 */
enum vdp22_ffmt {			/* Format of filter information */
	 VDP22_FFMT_VID = 1,		/* Vlan Identifier */
	 VDP22_FFMT_MACVID,		/* MAC address and Vlan Identifier */
	 VDP22_FFMT_GROUPVID,		/* Group and Vlan Identifier */
	 VDP22_FFMT_GROUPMACVID		/* Group, MAC and Vlan Identifier */
};

/*
 * Define VDP22 VSI Profile modes.
 */
enum vdp22_modes {
	VDP22_ENDTLV = 0,
	VDP22_PREASSOC = 1,
	VDP22_PREASSOC_WITH_RR,
	VDP22_ASSOC,
	VDP22_DEASSOC,
	VDP22_MGRID,
	VDP22_OUI = 0x7f
};

/*
 * Define VDP22 VSI identifier format
 */
enum vdp22_vsiid_fmt {
	VDP22_ID_IP4 = 1,		/* VSI ID is IPv4 address */
	VDP22_ID_IP6,			/* VSI ID is IPv6 address */
	VDP22_ID_MAC,			/* VSI ID is IEEE 802 MAC address */
	VDP22_ID_LOCAL,			/* VSI ID is locally defined */
	VDP22_ID_UUID			/* VSI ID is RFC4122 UUID */
};


/*
 * Define VDP22 Migiration hints
 */
enum vdp22_migration_hints {
	VDP22_MIGTO = 16,		/* M-bit migrate to hint */
	VDP22_MIGFROM = 32		/* S-bit migrate from hint */
};

#endif
