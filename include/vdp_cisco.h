/*******************************************************************************

  Implementation of Cisco Specific OUI for VDP2.2
  Copyright (c) 2012-2014 by Cisco Systems, Inc.

  Author(s): Padmanabhan Krishnan <padkrish at cisco dot com>

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

#ifndef __VDP22_VISCO_H__
#define __VDP22_VISCO_H__

#include "lldp.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "qbg_vdp22_oui.h"

#define MAX_VM_NAME 100
#define CISCO_OUI_VAL "00000C"
#define CISCO_OUI_HEX 0xC

#define CISCO_OUI_NAME_ARG_STR "vm_name"
#define CISCO_OUI_NAME_UUID_ARG_STR "vm_uuid"
#define CISCO_OUI_L3V4ADDR_ARG_STR "ipv4_addr"
#define MAX_VM_AF 3

#define KEYLEN          16
#define PORT_UUID_MAX 16

enum oui_key_arg {
	CISCO_OUI_NAME_ARG = 0,
	CISCO_OUI_NAME_UUID_ARG,
	CISCO_OUI_L3V4ADDR_ARG,
	CISCO_OUI_INVALID_ARG
};

enum cisco_oui_subtype {
	CISCO_OUI_NAME_SUBTYPE = 0xF1,
	CISCO_OUI_L3ADDR_SUBTYPE = 0xF2,
};

/*
 * Name SubTLV
 *     OUI:        => 3B = 00-00-0C
 *     subtype     => 1B = 0xF1
 *     VSI ID Frmt => 1B
 *     VSI ID      => 16B
 *     VM ID Frmt  => 1B
 *     VM ID       => 16B
 *     VM Name     => Variable
 *     Total       => 38 + VM name len
 */

/*
 * L3 Addr SubTLV
 *     OUI:        => 3B = 00-00-0C
 *     subtype     => 1B = 0xF2
 *     VSI ID Frmt => 1B
 *     VSI ID      => 16B
 *     AFI         => 2B
 *     L3 Addr     => Variable
 *     Total       => 23 + L3 Addr Len
 */

 /* Subtype Len w/o the 3B Cisco OUI Len */
enum cisco_oui_subtype_len {
	CISCO_VM_NAME_TLV_LEN = 35, /* minus the variable name len */
	CISCO_VM_L3ADDR_TLV_LEN = 20 /* minus the variable addr len */
};

struct oui_keyword_handler {
	char *keyword;
	enum oui_key_arg val;
};

typedef union l3_addrtype_ {
	struct in_addr   ipv4_address;
	struct in6_addr ipv6_address;
} l3_addr_t;

typedef struct vdp_cisco_oui_s {
	char key[KEYLEN];       /* Profile name */
	u8 uuid[PORT_UUID_MAX]; /* Instance ID */
	size_t vm_name_len;
	char vm_name[MAX_VM_NAME];
	u16 afi;
	u8 vm_addr_len;
	l3_addr_t l3_addr;
} vdp_cisco_oui_t;

bool cisco_str2vdpnl_hndlr(struct vdpnl_oui_data_s *, char *);
bool cisco_vdp_free_oui(struct vdp22_oui_data_s *);
bool cisco_vdpnl2vsi22_hndlr(void *, struct vdpnl_oui_data_s *,
			     struct vdp22_oui_data_s *);
size_t cisco_vdp_tx_hndlr(char unsigned *, struct vdp22_oui_data_s *, size_t);
bool cisco_vdp_rx_hndlr();
unsigned long cisco_vdp_oui_ptlvsize(void *);

static inline void fill_cisco_oui_type(unsigned char *oui_type)
{
	oui_type[0] = 0x00;
	oui_type[1] = 0x00;
	oui_type[2] = 0x0c;
}

#endif /* __VDP22_VISCO_H__ */
