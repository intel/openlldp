/*******************************************************************************

  implementation of ECP according to 802.1Qbg
  (c) Copyright IBM Corp. 2010

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>

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

#ifndef _ECP_H
#define _ECP_H

#include "lldp_mod.h"
#include "include/lldp_vdp.h"

#define ECP_SUBTYPE			0x0

#define ECP_MAX_RETRIES			3
#define ECP_SEQUENCE_NR_START		0x0

#define ECP_TRANSMISSION_TIMER(rte)	EVB_RTM(rte)*EVB_RTG
#define ECP_TRANSMISSION_DIVIDER	10000

typedef enum {
	ECP_REQUEST = 0,
	ECP_ACK
} ecp_mode;

struct ecp {
	struct l2_packet_data *l2;
	int sequence;
	int retries;
	int ackReceived;
	int ackTimerExpired;
	u16 lastSequence;
	u16 seqECPDU;
	struct portrx rx;
	struct porttx tx;
	struct portstats stats;
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

static const char *ecp_tx_states[] = {
	"ECP_TX_IDLE",
	"ECP_TX_INIT_TRANSMIT",
	"ECP_TX_TRANSMIT_ECPDU",
	"ECP_TX_WAIT_FOR_ACK",
	"ECP_TX_REQUEST_PDU"
};

enum {
	ECP_RX_IDLE,
	ECP_RX_INIT_RECEIVE,
	ECP_RX_RECEIVE_WAIT,
	ECP_RX_RECEIVE_ECPDU,
	ECP_RX_SEND_ACK,
	ECP_RX_RESEND_ACK,
};

static const char *ecp_rx_states[] = {
	"ECP_RX_IDLE",
	"ECP_RX_INIT_RECEIVE",
	"ECP_RX_RECEIVE_WAIT",
	"ECP_RX_RECEIVE_ECPDU",
	"ECP_RX_SEND_ACK",
	"ECP_RX_RESEND_ACK",
};

void ecp_rx_ReceiveFrame(void *, unsigned int, const u8 *, size_t );

#endif /* _ECP_H */
