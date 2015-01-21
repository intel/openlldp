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
 * Define for length of vid-mac-gid
 * VID in string cannot be more than 4B (Max is 4K)
 * MAC when represented as 11:22:33:44:55:66 has 17B
 * GID is 4B
 * The below should be more than sufficient.
 */
#define MAX_GID_MAC_VID_STR 50

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

enum vsi_key_arg {
	VSI_MODE_ARG = 0,
	VSI_MGRID2_ARG,
	VSI_TYPEID_ARG,
	VSI_TYPEIDVER_ARG,
/*	VSI_VSIIDFRMT_ARG, TODO */
	VSI_VSIID_ARG,
	VSI_FILTER_ARG,
	VSI_MAND_NUM_ARG,
	VSI_HINTS_ARG,
	VSI_INVALID_ARG
};

#define VSI22_ARG_MODE_STR "mode"
#define VSI22_ARG_MGRID_STR "mgrid2"
#define VSI22_ARG_TYPEID_STR "typeid"
#define VSI22_ARG_TYPEIDVER_STR "typeidver"
#define VSI22_ARG_VSIIDFRMT_STR "vsiidfrmt"
/*#define VSI22_ARG_VSIID_STR "vsiid" TODO*/
#define VSI22_ARG_VSIID_STR "uuid"
#define VSI22_ARG_HINTS_STR "hints"
#define VSI22_ARG_FILTER_STR "filter"
#define VSI22_ARG_OUI_STR "oui"

#endif
