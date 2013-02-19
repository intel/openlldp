/******************************************************************************

  Implementation of ECP according to 802.1Qbg
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

******************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <errno.h>

#include "eloop.h"
#include "lldp_ecp22.h"
#include "messages.h"
#include "lldp_qbg_utils.h"
#include "lldp/l2_packet.h"
#include "lldp_tlv.h"

#define ECP22_MAX_RETRIES_DEFAULT	(3)	/* Default # of max retries */
#define ECP22_ACK_TIMER_STOPPED		(-1)
/*
 * Defaults to 2ms wait time for acknowledgement packet reception.
 */
#define ECP22_ACK_TIMER_DEFAULT		(8)

static void ecp22_tx_run_sm(struct ecp22 *);

static const char *const ecp22_rx_states[] = {	/* Receive states verbatim */
	"ECP22_RX_BEGIN",
	"ECP22_RX_WAIT",
	"ECP22_RX_WAIT2",
	"ECP22_RX_FIRST",
	"ECP22_RX_REC_ECPDU",
	"ECP22_RX_NEW_ECPDU",
	"ECP22_RX_SEND_ACK"
};

static const char *const ecp22_tx_states[] = {	/* Transmit states verbatim */
	"ECP22_TX_BEGIN",
	"ECP22_TX_INIT",
	"ECP22_TX_TXMIT_ECPDU",
	"ECP22_TX_WAIT_FORREQ",
	"ECP22_TX_WAIT_ONDATA",
	"ECP22_TX_ERROR"
};

/*
 * Increment sequence number. Do not return zero as sequence number.
 */
static unsigned short inc_seqno(unsigned short x)
{
	++x;
	if (!x)		/* Wrapped */
		++x;
	return x;
}

/*
 * Find the ecp data associated with an interface.
 * Return pointer or NULL if not found.
 */
static struct ecp22 *find_ecpdata(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp = 0;

	if (eud) {
		LIST_FOREACH(ecp, &eud->head, node)
			if (!strncmp(ifname, ecp->ifname, IFNAMSIZ))
				break;
	}
	return ecp;
}

/*
 * ecp22_txframe - transmit ecp frame
 * @ecp: pointer to currently used ecp data structure
 *
 * returns the number of characters sent on success, -1 on failure
 *
 * sends out the frame stored in the frame structure using l2_packet_send.
 */
static int ecp22_txframe(struct ecp22 *ecp, char *txt, unsigned char *dst,
		       unsigned char *ack, size_t len)
{
	hexdump_frame(ecp->ifname, txt, ack, len);
	return l2_packet_send(ecp->l2, dst, htons(ETH_P_ECP22), ack, len);
}

/*
 * Append some data at the end of the transmit data buffer. Make sure the
 * End TLV always fits into the buffer.
 */
static unsigned char end_tlv[2] = { 0x0, 0x0 };		/* END TLV */

static void ecp22_append(u8 *buffer, u32 *pos, void *data, u32 len)
{
	if (*pos + len > ETH_FRAME_LEN - sizeof end_tlv)
		return;
	memcpy(buffer + *pos, data, len);
	*pos += len;
}

/*
 * Return a payload node to the freelist.
 */
void ecp22_putnode(struct ecp22_freelist *list, struct ecp22_payload_node *elm)
{
	elm->ptlv = free_pkd_tlv(elm->ptlv);
	if (list->freecnt > ecp22_maxpayload)
		free(elm);
	else {
		++list->freecnt;
		LIST_INSERT_HEAD(&list->head, elm, node);
	}
}

/*
 * ecp22_build_ecpdu - create an ecp protocol data unit
 * @ecp: pointer to currently used ecp data structure
 *
 * returns true on success, false on failure
 *
 * creates the frame header with the ports mac address, the ecp header with REQ
 * plus a packed TLVs created taken from the send queue.
 */
static bool ecp22_build_ecpdu(struct ecp22 *ecp)
{
	struct l2_ethhdr eth;
	struct ecp22_hdr ecph;
	u32 fb_offset = 0;
	struct packed_tlv *ptlv;
	struct ecp22_payload_node *p = LIST_FIRST(&ecp->inuse.head);

	if (!p)
		return false;
	ecp->tx.ecpdu_received = true;		/* Txmit buffer in use */
	memcpy(eth.h_dest, p->mac, ETH_ALEN);
	l2_packet_get_own_src_addr(ecp->l2, eth.h_source);
	eth.h_proto = htons(ETH_P_ECP22);
	memset(ecp->tx.frame, 0, sizeof ecp->tx.frame);
	ecp22_append(ecp->tx.frame, &fb_offset, (void *)&eth, sizeof eth);

	ecp22_hdr_set_version(&ecph, 1);
	ecp22_hdr_set_op(&ecph, ECP22_REQUEST);
	ecp22_hdr_set_subtype(&ecph, ECP22_VDP);
	ecph.ver_op_sub = htons(ecph.ver_op_sub);
	ecph.seqno = htons(ecp->tx.seqno);
	ecp22_append(ecp->tx.frame, &fb_offset, (void *)&ecph, sizeof ecph);

	ptlv = p->ptlv;
	ecp22_append(ecp->tx.frame, &fb_offset, ptlv->tlv, ptlv->size);
	ecp22_append(ecp->tx.frame, &fb_offset, end_tlv, sizeof end_tlv);
	ecp->tx.frame_len = MAX(fb_offset, (unsigned)ETH_ZLEN);
	LIST_REMOVE(p, node);
	ecp22_putnode(&ecp->isfree, p);
	LLDPAD_DBG("%s:%s seqno %#hx frame_len %#hx\n", __func__,
		   ecp->ifname, ecp->tx.seqno, ecp->tx.frame_len);
	return true;
}

/*
 * Execute transmit state transmitECPDU.
 */
static void ecp22_es_waitforreq(struct ecp22 *ecp)
{
	ecp->tx.retries = 0;
	ecp->tx.ack_received = false;
	ecp->tx.ecpdu_received = false;
	ecp->tx.seqno = inc_seqno(ecp->tx.seqno);
	LLDPAD_DBG("%s:%s seqno %#hx\n", __func__, ecp->ifname, ecp->tx.seqno);
}

/*
 * Execute transmit state countErrors.
 */
static void ecp22_es_counterror(struct ecp22 *ecp)
{
	++ecp->tx.errors;
	LLDPAD_DBG("%s:%s errors %lu\n", __func__, ecp->ifname,
		   ecp->tx.errors);
}

/*
 * Execute transmit state initTransmit.
 */
static void ecp22_es_inittransmit(struct ecp22 *ecp)
{
	ecp->tx.errors = 0;
	ecp->tx.seqno = 0;
}

/*
 * Return RTE value in milliseconds.
 */
static int rtevalue(unsigned char rte)
{
	return (1 << rte) * 10;
}

/*
 * ecp22_ack_timeout_handler - handles the ack timer expiry
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called when the ECP timer has expired. Calls the ECP station state machine.
 */
static void ecp22_ack_timeout_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct ecp22 *ecp = (struct ecp22 *)user_ctx;

	LLDPAD_DBG("%s:%s retries:%d\n", __func__,
		   ecp->ifname, ecp->tx.retries);
	ecp22_tx_run_sm(ecp);
}

/*
 * ecp22_tx_start_acktimer - starts the ECP ack timer
 * @ecp: pointer to currently used ecp data structure
 *
 * returns 0 on success, -1 on error
 *
 * starts the ack timer when a frame has been sent out.
 */
static void ecp22_tx_start_acktimer(struct ecp22 *ecp)
{
	unsigned long ack_sec = rtevalue(ecp->max_rte) / 1000000;
	unsigned long ack_usec = rtevalue(ecp->max_rte) % 1000000;

	LLDPAD_DBG("%s:%s [%ld.%06ld]\n", __func__, ecp->ifname, ack_sec,
		   ack_usec);
	eloop_register_timeout(ack_sec, ack_usec, ecp22_ack_timeout_handler,
			       0, (void *)ecp);
}

/*
 * ecp22_tx_change_state - changes the ecp tx sm state
 * @ecp: pointer to currently used ecp data structure
 * @newstate: new state for the sm
 *
 * no return value
 *
 * checks state transistion for consistency and finally changes the state of
 * the profile.
 */
static void ecp22_tx_change_state(struct ecp22 *ecp, unsigned char newstate)
{
	switch (newstate) {
	case ECP22_TX_BEGIN:
		break;
	case ECP22_TX_INIT:
		assert(ecp->tx.state == ECP22_TX_BEGIN);
		break;
	case ECP22_TX_WAIT_FORREQ:
		assert(ecp->tx.state == ECP22_TX_INIT ||
		       ecp->tx.state == ECP22_TX_ERROR ||
		       ecp->tx.state == ECP22_TX_TXMIT_ECPDU);
		break;
	case ECP22_TX_WAIT_ONDATA:
		assert(ecp->tx.state == ECP22_TX_WAIT_FORREQ);
		break;
	case ECP22_TX_TXMIT_ECPDU:
		assert(ecp->tx.state == ECP22_TX_WAIT_ONDATA);
		break;
	case ECP22_TX_ERROR:
		assert(ecp->tx.state == ECP22_TX_TXMIT_ECPDU);
		break;
	default:
		LLDPAD_ERR("%s: ECP TX state machine invalid state %d\n",
			   ecp->ifname, newstate);
	}
	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   ecp->ifname, ecp22_tx_states[ecp->tx.state],
		   ecp22_tx_states[newstate]);
	ecp->tx.state = newstate;
}

/*
 * Send the payload data.
 */
static int ecp22_es_txmit(struct ecp22 *ecp)
{
	int rc = 0;

	++ecp->tx.retries;
	ecp22_txframe(ecp, "ecp-out", ecp->tx.frame, ecp->tx.frame,
		      ecp->tx.frame_len);
	ecp22_tx_start_acktimer(ecp);
	return rc;
}

/*
 * ecp22_set_tx_state - sets the ecp tx state machine state
 * @ecp: pointer to currently used ecp data structure
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool ecp22_set_tx_state(struct ecp22 *ecp)
{
	struct port *port = port_find_by_name(ecp->ifname);

	if (!port) {
		LLDPAD_ERR("%s:%s port not found\n", __func__, ecp->ifname);
		return 0;
	}
	if ((port->portEnabled == false) && (port->prevPortEnabled == true)) {
		LLDPAD_ERR("%s:%s port was disabled\n", __func__, ecp->ifname);
		ecp22_tx_change_state(ecp, ECP22_TX_BEGIN);
	}
	port->prevPortEnabled = port->portEnabled;

	switch (ecp->tx.state) {
	case ECP22_TX_BEGIN:
		ecp22_tx_change_state(ecp, ECP22_TX_INIT);
		return true;
	case ECP22_TX_INIT:
		ecp22_tx_change_state(ecp, ECP22_TX_WAIT_FORREQ);
		return true;
	case ECP22_TX_WAIT_FORREQ:
		ecp22_tx_change_state(ecp, ECP22_TX_WAIT_ONDATA);
		return true;
	case ECP22_TX_WAIT_ONDATA:
		if (LIST_FIRST(&ecp->inuse.head)) {	/* Data to send */
			ecp22_build_ecpdu(ecp);
			ecp22_tx_change_state(ecp, ECP22_TX_TXMIT_ECPDU);
			return true;
		}
		return false;
	case ECP22_TX_TXMIT_ECPDU:
		if (ecp->tx.ack_received) {
			ecp22_tx_change_state(ecp, ECP22_TX_WAIT_FORREQ);
			return true;
		}
		if (ecp->tx.retries > ecp->max_retries) {
			ecp22_tx_change_state(ecp, ECP22_TX_ERROR);
			return true;
		}
		return false;
	case ECP22_TX_ERROR:
		ecp22_tx_change_state(ecp, ECP22_TX_WAIT_FORREQ);
		return true;
	default:
		LLDPAD_ERR("%s: ECP TX state machine in invalid state %d\n",
			   ecp->ifname, ecp->tx.state);
		return false;
	}
}

/*
 * ecp22_tx_run_sm - state machine for ecp transmit
 * @ecp: pointer to currently used ecp data structure
 *
 * no return value
 */
static void ecp22_tx_run_sm(struct ecp22 *ecp)
{
	ecp22_set_tx_state(ecp);
	do {
		LLDPAD_DBG("%s:%s state %s\n", __func__,
			   ecp->ifname, ecp22_tx_states[ecp->tx.state]);

		switch (ecp->tx.state) {
		case ECP22_TX_BEGIN:
			break;
		case ECP22_TX_INIT:
			ecp22_es_inittransmit(ecp);
			break;
		case ECP22_TX_WAIT_FORREQ:
			ecp22_es_waitforreq(ecp);
			break;
		case ECP22_TX_WAIT_ONDATA:
			break;
		case ECP22_TX_TXMIT_ECPDU:
			ecp22_es_txmit(ecp);
			break;
		case ECP22_TX_ERROR:
			ecp22_es_counterror(ecp);
			break;
		}
	} while (ecp22_set_tx_state(ecp) == true);
}

/*
 * ecp22_rx_change_state - changes the ecp rx sm state
 * @ecp: pointer to currently used ecp data structure
 * @newstate: new state for the sm
 *
 * no return value
 *
 * checks state transistion for consistency and finally changes the state of
 * the ecp receive buffer.
 */
static void ecp22_rx_change_state(struct ecp22 *ecp, u8 newstate)
{
	switch (newstate) {
	case ECP22_RX_BEGIN:
		break;
	case ECP22_RX_WAIT:
		assert(ecp->rx.state == ECP22_RX_BEGIN);
		break;
	case ECP22_RX_FIRST:
		assert(ecp->rx.state == ECP22_RX_WAIT);
		break;
	case ECP22_RX_REC_ECPDU:
		assert((ecp->rx.state == ECP22_RX_FIRST) ||
		       (ecp->rx.state == ECP22_RX_WAIT2));
		break;
	case ECP22_RX_NEW_ECPDU:
		assert(ecp->rx.state == ECP22_RX_REC_ECPDU);
		break;
	case ECP22_RX_SEND_ACK:
		assert((ecp->rx.state == ECP22_RX_REC_ECPDU) ||
		       (ecp->rx.state == ECP22_RX_NEW_ECPDU));
		break;
	case ECP22_RX_WAIT2:
		assert(ecp->rx.state == ECP22_RX_SEND_ACK);
		break;
	default:
		LLDPAD_ERR("%s:%s LLDP RX state machine invalid state %d\n",
			   __func__, ecp->ifname, newstate);
	}
	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   ecp->ifname, ecp22_rx_states[ecp->rx.state],
		   ecp22_rx_states[newstate]);
	ecp->rx.state = newstate;
}

/*
 * Execute action in state sendack. Construct and send an acknowledgement
 * for the received ECP packet.
 */
static void ecp22_es_send_ack(struct ecp22 *ecp)
{
	unsigned char ack_frame[ETH_HLEN + sizeof(struct ecp22_hdr)];
	struct ethhdr *ethdst = (struct ethhdr *)ack_frame;
	struct ecp22_hdr *ecpdst = (struct ecp22_hdr *)&ack_frame[ETH_HLEN];
	struct ethhdr *ethsrc = (struct ethhdr *)ecp->rx.frame;
	struct ecp22_hdr *ecpsrc = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];
	struct ecp22_hdr ack;

	LLDPAD_DBG("%s:%s state %s seqno %#hx\n", __func__, ecp->ifname,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.seqno);
	memcpy(ethdst->h_dest, nearest_customer_bridge, ETH_ALEN);
	l2_packet_get_own_src_addr(ecp->l2, (u8 *)&ethdst->h_source);
	ethdst->h_proto = ethsrc->h_proto;
	/* Set ECP header */
	ack.ver_op_sub = ntohs(ecpsrc->ver_op_sub);
	ecp22_hdr_set_op(&ack, ECP22_ACK);
	ecpdst->ver_op_sub = htons(ack.ver_op_sub);
	ecpdst->seqno = htons(ecp->rx.seqno);
	ecp22_txframe(ecp, "ecp-ack", ethsrc->h_source, ack_frame,
		      sizeof ack_frame);
}


/*
 * Notify upper layer protocol function of ECP payload data just received.
 */
static void ecp22_to_ulp(unsigned short ulp, struct ecp22 *ecp)
{
	size_t offset = ETH_HLEN + sizeof(struct ecp22_hdr);
	struct qbg22_imm to_ulp;

	to_ulp.data_type = ECP22_TO_ULP;
	to_ulp.u.c.len = ecp->rx.frame_len - offset;
	to_ulp.u.c.data =  &ecp->rx.frame[offset];
	if (ulp == ECP22_VDP)
		modules_notify(LLDP_MOD_VDP22, LLDP_MOD_ECP22, ecp->ifname,
			       &to_ulp);
	else
		LLDPAD_INFO("%s:%s ECP subtype %d not yet implemented\n",
			    __func__, ecp->ifname, ulp);
}

/*
 * Execute action in state newECPDU.
 * Notify upper layer protocol of new data.
 */
static void ecp22_es_new_ecpdu(struct ecp22 *ecp)
{
	struct ecp22_hdr *hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];
	struct ecp22_hdr ecphdr;
	unsigned short ulp;

	ecphdr.ver_op_sub = ntohs(hdr->ver_op_sub);
	ulp = ecp22_hdr_read_subtype(&ecphdr);
	LLDPAD_DBG("%s:%s state %s notify ULP %d seqno %#hx\n", __func__,
		   ecp->ifname, ecp22_rx_states[ecp->rx.state],
		   ulp, ecp->rx.seqno);
	ecp->rx.last_seqno = ecp->rx.seqno;
	ecp22_to_ulp(ulp, ecp);
}

/*
 * Execute action in state receiveECPDU.
 */
static void ecp22_es_rec_ecpdu(struct ecp22 *ecp)
{
	struct ecp22_hdr *hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];

	ecp->rx.seqno = ntohs(hdr->seqno);
	LLDPAD_DBG("%s:%s state %s seqno %#hx\n", __func__, ecp->ifname,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.seqno);
}

/*
 * Execute action in state receiveFirst.
 */
static void ecp22_es_first(struct ecp22 *ecp)
{
	struct ecp22_hdr *hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];

	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			ecp22_rx_states[ecp->rx.state]);
	ecp->rx.last_seqno = ntohs(hdr->seqno) - 1;
}

/*
 * Execute action in state receiveWait.
 */
static void ecp22_es_wait(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			ecp22_rx_states[ecp->rx.state]);
	ecp->rx.ecpdu_received = false;
}

/*
 * ecp22_set_rx_state - sets the ecp receive state machine state
 * @ecp: pointer to currently used ecp data structure
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. Returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool ecp22_set_rx_state(struct ecp22 *ecp)
{
	struct port *port = port_find_by_name(ecp->ifname);

	if (!port)
		return false;

	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			   ecp22_rx_states[ecp->rx.state]);
	if (port->portEnabled == false)
		ecp22_rx_change_state(ecp, ECP22_RX_BEGIN);
	switch (ecp->rx.state) {
	case ECP22_RX_BEGIN:
		ecp22_rx_change_state(ecp, ECP22_RX_WAIT);
		return false;
	case ECP22_RX_WAIT:
		if (ecp->rx.ecpdu_received) {
			ecp22_rx_change_state(ecp, ECP22_RX_FIRST);
			return true;
		}
		return false;
	case ECP22_RX_WAIT2:
		if (ecp->rx.ecpdu_received) {
			ecp22_rx_change_state(ecp, ECP22_RX_REC_ECPDU);
			return true;
		}
		return false;
	case ECP22_RX_FIRST:
		ecp22_rx_change_state(ecp, ECP22_RX_REC_ECPDU);
		return true;
	case ECP22_RX_REC_ECPDU:
		if (ecp->rx.seqno == ecp->rx.last_seqno)
			ecp22_rx_change_state(ecp, ECP22_RX_SEND_ACK);
		else
			ecp22_rx_change_state(ecp, ECP22_RX_NEW_ECPDU);
		return true;
	case ECP22_RX_NEW_ECPDU:
		ecp22_rx_change_state(ecp, ECP22_RX_SEND_ACK);
		return true;
	case ECP22_RX_SEND_ACK:
		ecp22_rx_change_state(ecp, ECP22_RX_WAIT2);
		return true;
	default:
		LLDPAD_DBG("%s:%s ECP RX state machine in invalid state %d\n",
			   __func__, ecp->ifname, ecp->rx.state);
		return false;
	}
}

/*
 * ecp22_rx_run_sm - state machine for ecp receive protocol
 * @ecp: pointer to currently used ecp data structure
 *
 * no return value
 *
 * runs the state machine for ecp22 receive function.
 */
static void ecp22_rx_run_sm(struct ecp22 *ecp)
{
	ecp22_set_rx_state(ecp);
	do {
		switch (ecp->rx.state) {
		case ECP22_RX_WAIT:
		case ECP22_RX_WAIT2:
			ecp22_es_wait(ecp);
			break;
		case ECP22_RX_FIRST:
			ecp22_es_first(ecp);
			break;
		case ECP22_RX_REC_ECPDU:
			ecp22_es_rec_ecpdu(ecp);
			break;
		case ECP22_RX_NEW_ECPDU:
			ecp22_es_new_ecpdu(ecp);
			break;
		case ECP22_RX_SEND_ACK:
			ecp22_es_send_ack(ecp);
			break;
		default:
			LLDPAD_DBG("%s:%s ECP RX state machine in invalid "
				   "state %d\n", __func__, ecp->ifname,
				   ecp->rx.state);
		}
	} while (ecp22_set_rx_state(ecp) == true);
}

/*
 * Received an aknowledgement frame.
 * Check if we have a transmit pending and the ack'ed packet number matches
 * the send packet.
 */
static void ecp22_recack_frame(struct ecp22 *ecp, unsigned short seqno)
{
	LLDPAD_DBG("%s:%s txmit:%d seqno %#hx ack-seqno %#hx\n", __func__,
		   ecp->ifname, ecp->tx.ecpdu_received, ecp->tx.seqno, seqno);
	if (ecp->tx.ecpdu_received) {
		if (ecp->tx.seqno == seqno)
			ecp->tx.ack_received = true;
	}
}

/*
 * ecp22_rx_receiveframe - receive am ecp frame
 * @ctx: rx callback context, struct ecp * in this case
 * @ifindex: index of interface
 * @buf: buffer which contains the frame just received
 * @len: size of buffer (frame)
 *
 * no return value
 *
 * creates a local copy of the buffer and checks the header. keeps some
 * statistics about ecp frames. Checks if it is a request or an ack frame and
 * branches to ecp rx or ecp tx state machine.
 */
static void ecp22_rx_receiveframe(void *ctx, int ifindex, const u8 *buf,
				  size_t len)
{
	struct ecp22 *ecp = (struct ecp22 *)ctx;
	struct port *port;
	struct ecp22_hdr *ecp_hdr, ecphdr;

	LLDPAD_DBG("%s:%s ifindex:%d len:%zd state:%s ecpdu_received:%d\n",
		   __func__, ecp->ifname, ifindex, len,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.ecpdu_received);
	hexdump_frame(ecp->ifname, "frame-in", buf, len);
	port = port_find_by_name(ecp->ifname);
	if (!port || ecp->rx.ecpdu_received)
		/* Port not found or buffer not free */
		return;

	memcpy(ecp->rx.frame, buf, len);
	ecp->rx.frame_len = len;
	ecp->stats.statsFramesInTotal++;

	ecp_hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];
	ecphdr.ver_op_sub = ntohs(ecp_hdr->ver_op_sub);

	/* Check for correct subtype and version number */
	if (ecp22_hdr_read_version(&ecphdr) != 1) {
		LLDPAD_ERR("%s:%s ERROR unknown version %#02hx seqno %#hx\n",
			   __func__, ecp->ifname, ecphdr.ver_op_sub,
			   ntohs(ecp_hdr->seqno));
		return;
	}
	switch (ecp22_hdr_read_subtype(&ecphdr)) {
	default:
		LLDPAD_ERR("%s:%s ERROR unknown subtype %#02hx seqno %#hx\n",
			   __func__, ecp->ifname, ecphdr.ver_op_sub,
			   ntohs(ecp_hdr->seqno));
		return;
	case ECP22_PECSP:
	case ECP22_VDP:
		/* Subtype ok, fall through intended */
		break;
	}

	switch (ecp22_hdr_read_op(&ecphdr)) {
	case ECP22_REQUEST:
		LLDPAD_DBG("%s:%s received REQ frame seqno %#hx\n", __func__,
			   ecp->ifname, ntohs(ecp_hdr->seqno));
		ecp->rx.ecpdu_received = true;
		ecp22_rx_run_sm(ecp);
		break;
	case ECP22_ACK:
		LLDPAD_DBG("%s:%s received ACK frame seqno %#hx\n", __func__,
			   ecp->ifname, ntohs(ecp_hdr->seqno));
		ecp22_recack_frame(ecp, ntohs(ecp_hdr->seqno));
		break;
	default:
		LLDPAD_ERR("%s:%s ERROR unknown mode %#02hx seqno %#hx\n",
			   __func__, ecp->ifname, ecphdr.ver_op_sub,
			   ntohs(ecp_hdr->seqno));
	}
}

/*
 * ecp22_create - create data structure and initialize ecp protocol
 * @ifname: interface for which the ecp protocol is initialized
 *
 * returns NULL on error and an pointer to the ecp22 structure on success.
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming ecp frames and initializes the ecp rx and tx state machines.
 * To be called when a successful exchange of EVB TLVs has been
 * made and ECP protocols are supported by both sides.
 */
static struct ecp22 *ecp22_create(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp;

	ecp = calloc(1, sizeof *ecp);
	if (!ecp) {
		LLDPAD_ERR("%s:%s unable to allocate ecp protocol\n", __func__,
			   ifname);
		return NULL;
	}
	strncpy(ecp->ifname, ifname, sizeof ecp->ifname);
	ecp->l2 = l2_packet_init(ecp->ifname, 0, ETH_P_ECP22,
				 ecp22_rx_receiveframe, ecp, 1);

	if (!ecp->l2) {
		LLDPAD_ERR("%s:%s error open layer 2 ETH_P_ECP\n", __func__,
			   ifname);
		free(ecp);
		return NULL;
	}
	LIST_INSERT_HEAD(&eud->head, ecp, node);
	LLDPAD_DBG("%s:%s create ecp data\n", __func__, ifname);
	return ecp;
}

/*
 * ecp22_start - build up ecp structures for an interface
 * @ifname: name of the interface
 */
void ecp22_start(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s start ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	if (!eud) {
		LLDPAD_DBG("%s:%s no ECP module\n", __func__, ifname);
		return;
	}
	ecp = find_ecpdata(ifname, eud);
	if (!ecp)
		ecp = ecp22_create(ifname, eud);
	ecp->max_retries = ECP22_MAX_RETRIES_DEFAULT;
	ecp->max_rte = ECP22_ACK_TIMER_DEFAULT;
	LIST_INIT(&ecp->inuse.head);
	ecp->inuse.last = 0;
	LIST_INIT(&ecp->isfree.head);
	ecp->isfree.freecnt = 0;
	ecp->rx.state = ECP22_RX_BEGIN;
	ecp22_rx_run_sm(ecp);
	ecp->tx.state = ECP22_TX_BEGIN;
	ecp22_tx_run_sm(ecp);
}

/*
 * Remove the ecp_payload nodes
 */
static void ecp22_removelist(ecp22_list *ptr)
{
	struct ecp22_payload_node *np;

	while ((np = LIST_FIRST(ptr))) {
		LIST_REMOVE(np, node);
		np->ptlv = free_pkd_tlv(np->ptlv);
		free(np);
	}
}

static void ecp22_remove(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s remove ecp\n", __func__, ecp->ifname);
	ecp22_removelist(&ecp->inuse.head);
	ecp->inuse.last = 0;
	ecp22_removelist(&ecp->isfree.head);
	ecp->isfree.freecnt = 0;
	LIST_REMOVE(ecp, node);
	free(ecp);
}

/*
 * ecp22_stop - tear down ecp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 */
void ecp22_stop(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s stop ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	ecp = find_ecpdata(ifname, eud);
	if (ecp)
		ecp22_remove(ecp);
}

/*
 * Update data exchanged via EVB protocol.
 * Returns true when data update succeeded.
 */
static int data_from_evb(char *ifname, struct evb22_to_ecp22 *ptr)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	ecp = find_ecpdata(ifname, eud);
	if (ecp) {
		ecp->max_rte = ptr->max_rte;
		ecp->max_retries = ptr->max_retry;
		return 0;
	}
	return -ENOENT;
}

/*
 * Add ecp payload data at the end of the queue.
 */
static void ecp22_add_payload(struct ecp22 *ecp,
			      struct ecp22_payload_node *elem)
{
	if (LIST_EMPTY(&ecp->inuse.head))
		LIST_INSERT_HEAD(&ecp->inuse.head, elem, node);
	else
		LIST_INSERT_AFTER(ecp->inuse.last, elem, node);
	ecp->inuse.last = elem;
	if (!ecp->tx.ecpdu_received)	/* Transmit buffer free */
		ecp22_tx_run_sm(ecp);
}

/*
 * Copy the payload data.
 */
static struct packed_tlv *copy_ptlv(struct packed_tlv *from)
{
	struct packed_tlv *ptlv = create_ptlv();

	if (!ptlv)
		return NULL;
	ptlv->size = from->size;
	ptlv->tlv = calloc(ptlv->size, sizeof(unsigned char));
	if (!ptlv->tlv) {
		free_pkd_tlv(ptlv);
		return NULL;
	}
	memcpy(ptlv->tlv, from->tlv, from->size);
	return ptlv;
}

/*
 * Create a node for the ecp payload data. Get it from the free list if not
 * empty. Otherwise allocate from heap.
 */
static struct ecp22_payload_node *ecp22_getnode(struct ecp22_freelist *list)
{
	struct ecp22_payload_node *elem = LIST_FIRST(&list->head);

	if (!elem)
		elem = calloc(1, sizeof *elem);
	else {
		LIST_REMOVE(elem, node);
		--list->freecnt;
	}
	return elem;
}

/*
 * Receive upper layer protocol data unit for transmit.
 * Returns error if the request could not be queued for transmision.
 */
static int ecp22_req2send(char *ifname, unsigned short subtype,
			  unsigned const char *mac, struct packed_tlv *du)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;
	struct ecp22_payload_node *payda;
	struct packed_tlv *ptlv = copy_ptlv(du);
	int rc = 0;

	LLDPAD_DBG("%s:%s subtype:%d\n", __func__, ifname, subtype);

	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	ecp = find_ecpdata(ifname, eud);
	if (!ecp) {
		rc = -ENODEV;
		goto out;
	}
	if (!ptlv) {
		rc = -ENOMEM;
		goto out;
	}
	if (ptlv->size >= ECP22_MAXPAYLOAD_LEN) {
		rc = -E2BIG;
		goto out;
	}
	payda = ecp22_getnode(&ecp->isfree);
	if (!payda) {
		free_pkd_tlv(ptlv);
		rc = -ENOMEM;
		goto out;
	}
	payda->ptlv = ptlv;
	payda->subtype = subtype;
	memcpy(payda->mac, mac, sizeof payda->mac);
	ecp22_add_payload(ecp, payda);
out:
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, ifname, rc);
	return rc;
}

/*
 * Payload data from VDP module.
 * Returns true when data update succeeded.
 */
static int data_from_vdp(char *ifname, struct ecp22_to_ulp *ptr)
{
	struct packed_tlv d;

	d.size = ptr->len;
	d.tlv = ptr->data;
	return ecp22_req2send(ifname, ECP22_VDP, nearest_customer_bridge, &d);
}

/*
 * Handle notifications from other modules. Check if sender-id and data type
 * indicator match. Return false when data could not be delivered.
 */
static int ecp22_notify(int sender_id, char *ifname, void *data)
{
	struct qbg22_imm *qbg = (struct qbg22_imm *)data;

	LLDPAD_DBG("%s:%s sender-id:%#x data_type:%d\n", __func__, ifname,
		   sender_id, qbg->data_type);
	if (sender_id == LLDP_MOD_EVB22 && qbg->data_type == EVB22_TO_ECP22)
		return data_from_evb(ifname, &qbg->u.a);
	if (sender_id == LLDP_MOD_VDP22 && qbg->data_type == VDP22_TO_ECP22)
		return data_from_vdp(ifname, &qbg->u.c);
	return 0;
}

static const struct lldp_mod_ops ecp22_ops =  {
	.lldp_mod_register = ecp22_register,
	.lldp_mod_unregister = ecp22_unregister,
	.lldp_mod_notify = ecp22_notify
};

/*
 * ecp22_register - register ecp module to lldpad
 *
 * returns lldp_module struct on success, NULL on error
 *
 * allocates a module structure with ecp module information and returns it
 * to lldpad.
 */
struct lldp_module *ecp22_register(void)
{
	struct lldp_module *mod;
	struct ecp22_user_data *eud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s:can not allocate ecp module data\n", __func__);
		return NULL;
	}
	eud = calloc(1, sizeof(struct ecp22_user_data));
	if (!eud) {
		free(mod);
		LLDPAD_ERR("%s:can not allocate ecp user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&eud->head);
	mod->id = LLDP_MOD_ECP22;
	mod->ops = &ecp22_ops;
	mod->data = eud;
	LLDPAD_DBG("%s: done\n", __func__);
	return mod;
}

/*
 * ecp22_free_data - frees up ecp data chain
 */
static void ecp22_free_data(struct ecp22_user_data *ud)
{
	struct ecp22 *ecp;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ecp = LIST_FIRST(&ud->head);
			ecp22_remove(ecp);
		}
	}
}

/*
 * ecp22_unregister - unregister ecp module from lldpad
 *
 * no return value
 *
 * frees ecp module structure and user data.
 */
void ecp22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		ecp22_free_data((struct ecp22_user_data *)mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s: done\n", __func__);
}
