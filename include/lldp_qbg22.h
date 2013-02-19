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
 * Define IEEE 802.1Qbg module identification numbers and module interface
 * structures which are exchanged between all the qbg modules.
 *
 * Messages are sent from:
 * EVB --> ECP: Max number of retries (R) and retransmit timeout (RTE).
 *
 * EVB --> VDP: Max number of Reinit-keep-Alive (RKA) Resource wait delay (RWD)
 *		and groupid support.
 *
 * VDP --> ECP: VSI Information as payload
 * ECP --> VDP: VSI Information as payload
 *
 * This is used in the module notify call back function.
 */

#ifndef LLDP_QBG22_H
#define LLDP_QBG22_H

/*
 * Modules Identifications
 */
#define LLDP_MOD_EVB22		0x80c2
#define	LLDP_MOD_ECP22		0x80c3
#define	LLDP_MOD_VDP22		0x80c4


enum {				/* Identify data type in union below */
	EVB22_TO_ECP22 = 1,	/* Data from EVB to ECP */
	EVB22_TO_VDP22 = 2,	/* Data from EVB to VDP */
	ECP22_TO_ULP = 3,	/* Data from ECP to VDP, etc */
	VDP22_TO_ECP22 = 4,	/* Data from VDP to ECP */
	/* ECP22 subtypes */
	ECP22_VDP = 1,		/* VDP protocol */
	ECP22_PECSP = 2		/* Port extender control and status protocol */
};

struct evb22_to_ecp22 {		/* Notification from EVB to ECP */
	unsigned char max_retry;/* Max number of retries */
	unsigned char max_rte;	/* Max number of acknowledgement wait */
};

struct evb22_to_vdp22 {		/* Notification from EVB to VDP */
	unsigned char max_rwd;	/* Max number of resource wait delay */
	unsigned char max_rka;	/* Max number of reinit keep alive */
	unsigned char gpid;	/* Support group ids in VDP */
};

struct ecp22_to_ulp {		/* Notification from ECP to VDP, etc */
	unsigned short len;	/* Size of bytestream */
	void *data;		/* Pointer to data */
};

struct qbg22_imm {		/* Intermodule message data structure */
	int data_type;		/* Identifies union data */
	union {			/* Overlay possible data */
		struct evb22_to_ecp22 a;
		struct evb22_to_vdp22 b;
		struct ecp22_to_ulp c;
	} u;
};
#endif
