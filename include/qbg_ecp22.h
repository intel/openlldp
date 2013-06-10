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

#ifndef QBG_ECP22_H
#define QBG_ECP22_H

#include <linux/if_ether.h>

#include "lldp_mod.h"
#include "qbg22.h"

enum {					/* ECP Receive states */
	ECP22_RX_BEGIN,
	ECP22_RX_WAIT,
	ECP22_RX_WAIT2,
	ECP22_RX_FIRST,
	ECP22_RX_REC_ECPDU,
	ECP22_RX_NEW_ECPDU,
	ECP22_RX_SEND_ACK
};
enum {					/* ECP Transmit states */
	ECP22_TX_BEGIN,
	ECP22_TX_INIT,
	ECP22_TX_TXMIT_ECPDU,
	ECP22_TX_WAIT_FORREQ,
	ECP22_TX_WAIT_ONDATA,
	ECP22_TX_ERROR
};

enum {
	ECP22_REQUEST = 0,
	ECP22_ACK
} ecp22_mode;

struct ecp22_hdr {		/* ECP22 header */
	u16 ver_op_sub;		/* ECP22 version, operation, subtype */
	u16 seqno;		/* ECP22 sequence number */
} __attribute__ ((__packed__));

/*
 * Define maximum ECP protocol payload length. Leave room for END TLV.
 */
#define	ECP22_MAXPAYLOAD_LEN	(ETH_DATA_LEN - sizeof(struct ecp22_hdr) - 2)

struct ecp22_buffer {			/* ECP payload buffer */
	unsigned char frame[ETH_FRAME_LEN];	/* Payload buffer */
	unsigned short frame_len;	/* # of bytes of valid data */
	unsigned char state;		/* Buffer state machine */
	unsigned char ecpdu_received;	/* True when packet received */
	unsigned char ack_received;	/* True when packet acknowledged */
	unsigned char retries;		/* # of retries */
	unsigned short last_seqno;	/* Seqno last acknowledged packet */
	unsigned short seqno;		/* Seqno this packet */
	unsigned long errors;		/* # of transmit errors */
};

struct ecp22_payload_node {		/* ECP Payload node */
	struct packed_tlv *ptlv;	/* Pointer to packed TLV to send */
	unsigned short subtype;		/* ECP subtype*/
	unsigned char mac[ETH_ALEN];	/* Destination MAC address */
	LIST_ENTRY(ecp22_payload_node) node;
};

/*
 * ECP22 payload data
 */
typedef LIST_HEAD(ecp22_list, ecp22_payload_node) ecp22_list;

struct ecp22_usedlist {			/* List of valid ecp_payload_nodes */
	ecp22_list head;		/* ECP payload data free list */
	struct ecp22_payload_node *last;	/* Ptr to last entry in list */
};

struct ecp22_freelist {		/* List of free ecp_payload_nodes */
	ecp22_list head;	/* ECP payload data free list */
	u16 freecnt;		/* # of nodes on freelist */
};

enum {
	ecp22_maxpayload = 64
};

struct ecp22 {			/* ECP protocol data per interface */
	struct l2_packet_data *l2;
	char ifname[IFNAMSIZ];		/* Interface name */
	LIST_ENTRY(ecp22) node;		/* Successor */
	struct ecp22_buffer rx;		/* Receive buffer */
	struct ecp22_buffer tx;		/* Transmit buffer */
	struct agentstats stats;
	struct ecp22_usedlist inuse;	/* List of payload data */
	struct ecp22_freelist isfree;	/* List of free payload nodes */
	unsigned char max_retries;	/* Max # of retries (via EVB) */
	unsigned char max_rte;		/* Wait time for ack (via EVB) */
};

struct ecp22_user_data {		/* ECP module data per interface  */
	LIST_HEAD(ecp_head, ecp22) head;
};

/*
 * Function prototypes
 */
struct lldp_module *ecp22_register(void);
void ecp22_unregister(struct lldp_module *);
void ecp22_stop(char *);
void ecp22_start(char *);

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
	return (p->ver_op_sub >> 12) & 0xf;
}

#endif
