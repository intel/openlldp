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

#ifndef LLDP_ECP22_H
#define LLDP_ECP22_H

#include "lldp_mod.h"

#define	LLDP_MOD_ECP22			0x80c3
#define	ETH_P_ECP22			0x8890

enum {
	ECP22_REQUEST = 0,
	ECP22_ACK
} ecp22_mode;

struct ecp22 {			/* ECP protocol data per interface */
	struct l2_packet_data *l2;
	char ifname[IFNAMSIZ];
	LIST_ENTRY(ecp22) node;
};

struct ecp22_user_data {		/* ECP module data per interface  */
	LIST_HEAD(ecp_head, ecp22) head;
};

struct lldp_module *ecp22_register(void);
void ecp22_unregister(struct lldp_module *);
void ecp22_stop(char *);
void ecp22_start(char *);

struct ecp22_hdr {		/* ECP header */
	u16	ver_op_sub;	/* ECP version, operation, subtype */
	u16	seqno;		/* ECP sequence number */
} __attribute__ ((__packed__));

/*
 * Functions to set and read ecp header operations field.
 */
static inline void ecp22_hdr_set_op(struct ecp22_hdr *p, unsigned int op)
{
	p->ver_op_sub &= 0xf3ff;
	p->ver_op_sub |= (op & 0x3) << 10;
}

static inline unsigned int ecp22_hdr_read_op(struct ecp22_hdr *p)
{
	return (p->ver_op_sub >> 10) & 3;
}

/*
 * Functions to set and read ecp header subtype field.
 */
static inline void ecp22_hdr_set_subtype(struct ecp22_hdr *p, unsigned int sub)
{
	p->ver_op_sub &= 0xfc00;
	p->ver_op_sub |= sub & 0x3ff;
}

static inline unsigned int ecp22_hdr_read_subtype(struct ecp22_hdr *p)
{
	return p->ver_op_sub & 0x3ff;
}

/*
 * Functions to set and read ecp header version field.
 */
static inline void ecp22_hdr_set_version(struct ecp22_hdr *p, unsigned int ver)
{
	p->ver_op_sub &= 0xfff;
	p->ver_op_sub |= (ver & 0xf) << 12;
}

static inline unsigned int ecp22_hdr_read_version(struct ecp22_hdr *p)
{
	return p->ver_op_sub & 0x3ff;
}

#endif /* _ECP_H */
