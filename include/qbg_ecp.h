/*******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>
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

#ifndef QBG_ECP_H
#define QBG_ECP_H

#include <linux/if_ether.h>

#include "lldp_mod.h"
#include "qbg_vdp.h"

#define ECP_SUBTYPE			0x0

#define ECP_MAX_RETRIES			3
#define ECP_SEQUENCE_NR_START		0x0

#define MSECS				1000
#define SECS				(1000 * MSECS)

#define ECP_ACK_TIMER_DEFAULT		(500 * MSECS)	/* 500 ms */
#define ECP_LOCALCHANGE_TIMEOUT		(1 * MSECS)	/* 1 ms */

#define ECP_ACK_TIMER_STOPPED		(-1)

typedef enum {
	ECP_REQUEST = 0,
	ECP_ACK
} ecp_mode;

struct ecp_buffer {			/* ECP payload buffer */
	u8 frame[ETH_FRAME_LEN];	/* Payload buffer */
	u16 frame_len;			/* # of bytes of valid data */
	u8 state;			/* Buffer state */
	u8 localChange;			/* Status changed */
	u8 rcvFrame;			/* True if new frame received */
};

struct ecp {
	struct l2_packet_data *l2;
	int sequence;
	int retries;
	int ackReceived;
	int ackTimer;
	u16 lastSequence;
	u16 seqECPDU;
	struct ecp_buffer rx;		/* Receive buffer */
	struct ecp_buffer tx;		/* Transmit buffer */
	struct agentstats stats;
	char ifname[IFNAMSIZ];		/* Interface name */
};

struct ecp_hdr {
	u8 oui[3];
	u8 pad1;
	u16 subtype;
	u8 mode;
	u16 seqnr;
} __attribute__ ((__packed__));

enum {
	ECP_TX_INIT_TRANSMIT,
	ECP_TX_TRANSMIT_ECPDU,
	ECP_TX_WAIT_FOR_ACK,
	ECP_TX_REQUEST_PDU
};

enum {
	ECP_RX_IDLE,
	ECP_RX_INIT_RECEIVE,
	ECP_RX_RECEIVE_WAIT,
	ECP_RX_RECEIVE_ECPDU,
	ECP_RX_SEND_ACK,
	ECP_RX_RESEND_ACK,
};

struct vdp_data;

void ecp_somethingChangedLocal(struct vdp_data *, bool);
void ecp_rx_send_ack_frame(struct vdp_data *);

int ecp_init(char *);
int ecp_deinit(char *);
#endif /* _ECP_H */
