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

#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <assert.h>
#include <linux/if_bridge.h>

#include "eloop.h"
#include "lldp.h"
#include "lldp_evb.h"
#include "lldp_qbg_utils.h"
#include "lldp_vdp.h"
#include "messages.h"
#include "config.h"
#include "lldp/l2_packet.h"

#include "lldp_tlv.h"

static void ecp_tx_run_sm(struct vdp_data *);
static void ecp_rx_run_sm(struct vdp_data *);

/* ecp_localchange_handler - triggers the processing of a local change
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called from ecp_somethingchangedlocal when a change is pending. Calls
 * the ECP tx station state machine. A oneshot handler. This detour is taken
 * to not having to call the ecp code from the vdp state machine. Instead, we
 * return to the event loop, giving other code a chance to do work.
 */
static void ecp_localchange_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vdp_data *vd;

	vd = (struct vdp_data *) user_ctx;
	if (vd->ecp.tx.localChange) {
		LLDPAD_DBG("%s:%s ecp.tx.localChange %i\n",
			   __func__, vd->ecp.ifname, vd->ecp.tx.localChange);
		ecp_tx_run_sm(vd);
	}
}

/* ecp_start_localchange_timer - starts the ECP localchange timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the ECP localchange timer when a localchange has been signaled from
 * the VDP state machine.
 */
static int ecp_start_localchange_timer(struct vdp_data *vd)
{
	return eloop_register_timeout(0, ECP_LOCALCHANGE_TIMEOUT,
				      ecp_localchange_handler,
				      NULL, (void *) vd);
}

/* ecp_stop_localchange_timer - stop the ECP localchange timer
 * @vd: vdp_data for the interface
 *
 * returns the number of removed handlers
 *
 * stops the ECP localchange timer. Used e.g. when the host interface goes down.
 */
static int ecp_stop_localchange_timer(struct vdp_data *vd)
{
	LLDPAD_DBG("%s:%s stopping ecp localchange timer\n", __func__,
		   vd->ecp.ifname);
	return eloop_cancel_timeout(ecp_localchange_handler, NULL, (void *) vd);
}

/* ecp_ackTimer_expired - checks for expired ack timer
 * @vd: vdp_data for interface
 *
 * returns true or false
 *
 * returns true if ack timer has expired, false otherwise.
 */
static bool ecp_ackTimer_expired(struct vdp_data *vd)
{
	return (vd->ecp.ackTimer == 0);
}

/* ecp_ack_timeout_handler - handles the ack timer expiry
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called when the ECP timer has expired. Calls the ECP station state machine.
 */
static void ecp_ack_timeout_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vdp_data *vd;

	vd = (struct vdp_data *) user_ctx;
	if (vd->ecp.ackTimer > 0)
		vd->ecp.ackTimer -= ECP_ACK_TIMER_DEFAULT;

	if (ecp_ackTimer_expired(vd) == true) {
		LLDPAD_DBG("%s:%s ecp_ackTimer_expired (%i)\n",
			   __func__, vd->ecp.ifname, vd->ecp.ackTimer);
		ecp_tx_run_sm(vd);
	} else {
		LLDPAD_DBG("%s:%s BUG! handler called but"
			   "vdp->ecp.ackTimer not expired (%i)\n",
			   __func__, vd->ecp.ifname, vd->ecp.ackTimer);
	}
}

/* ecp_start_ack_timer - starts the ECP ack timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the ECP ack timer when a frame has been sent out.
 */
static int ecp_start_ack_timer(struct vdp_data *vd)
{
	return eloop_register_timeout(0, ECP_ACK_TIMER_DEFAULT,
				      ecp_ack_timeout_handler,
				      NULL, (void *) vd);
}

/* ecp_stop_ack_timer - stop the ECP ack timer
 * @vd: vdp_data for the interface
 *
 * returns the number of removed handlers
 *
 * stops the ECP ack timer. Used e.g. when the host interface goes down.
 */
static int ecp_stop_ack_timer(struct vdp_data *vd)
{
	LLDPAD_DBG("%s:%s stopping ecp ack timer\n", __func__, vd->ecp.ifname);
	return eloop_cancel_timeout(ecp_ack_timeout_handler, NULL, (void *) vd);
}

/* ecp_tx_stop_ackTimer - stop the ECP ack timer
 * @vd: currently used port
 *
 * returns the number of removed handlers
 *
 * stops the ECP ack timer. used when a ack frame for the port has been
 * received.
 */
static void ecp_tx_stop_ackTimer(struct vdp_data *vd)
{
	vd->ecp.ackTimer = ECP_ACK_TIMER_STOPPED;
	LLDPAD_DBG("%s:%s stopped ecp ack timer\n", __func__, vd->ecp.ifname);
	ecp_stop_ack_timer(vd);
}

int ecp_deinit(char *ifname)
{
	struct vdp_data *vd;

	LLDPAD_DBG("%s:%s stopping ECP\n", __func__, ifname);
	vd = vdp_data(ifname);
	if (!vd) {
		LLDPAD_ERR("%s:%s unable to find vd\n", __func__, ifname);
		return -1;
	}

	ecp_stop_ack_timer(vd);
	ecp_stop_localchange_timer(vd);
	ecp_tx_stop_ackTimer(vd);
	return 0;
}

static const char *ecp_tx_states[] = {
	"ECP_TX_INIT_TRANSMIT",
	"ECP_TX_TRANSMIT_ECPDU",
	"ECP_TX_WAIT_FOR_ACK",
	"ECP_TX_REQUEST_PDU"
};

/* ecp_somethingChangedLocal - set flag if port has changed
 * @vd: port to set the flag for
 * @mode: mode to set the flag to
 *
 * no return value
 *
 * set the localChange flag with a mode to indicate a port has changed.
 * used  to signal an ecpdu needs to be sent out.
 */

void ecp_somethingChangedLocal(struct vdp_data *vd, bool flag)
{
	if (!vd)
		return;

	LLDPAD_DBG("%s:%s vd->ecp.tx.localChange to %s\n", __func__,
		   vd->ecp.ifname, (flag == true) ? "true" : "false");
	vd->ecp.tx.localChange = flag;
	ecp_start_localchange_timer(vd);
}

/*
 * Append some data at the end of the transmit data buffer. Make sure the
 * End TLV always fits into the buffer.
 */
static u8 end_tlv[2] = { 0x0, 0x0 };		/* END TLV */

static int ecp_append(u8 *buffer, u32 *pos, void *data, u32 len)
{
	if (*pos + len > ETH_FRAME_LEN - sizeof end_tlv)
		return 0;
	memcpy(buffer + *pos, data, len);
	*pos += len;
	return 1;
}

/* ecp_build_ECPDU - create an ecp protocol data unit
 * @vd: currently used port
 *
 * returns true on success, false on failure
 *
 * creates the frame header with the ports mac address, the ecp header with REQ
 * plus a list of packed TLVs created from the profiles on this
 * port.
 */
static bool ecp_build_ECPDU(struct vdp_data *vd)
{
	struct l2_ethhdr eth;
	struct ecp_hdr ecp_hdr;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	struct packed_tlv *ptlv =  NULL;
	struct vsi_profile *p;
	int rc;

	/* TODO: use LLDP group MAC addresses to support
	 *	 S-channels/multichannel
	 */
	memcpy(eth.h_dest, nearest_bridge, ETH_ALEN);
	l2_packet_get_own_src_addr(vd->ecp.l2,(u8 *)&own_addr);
	memcpy(eth.h_source, &own_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_ECP);
	memset(vd->ecp.tx.frame, 0, sizeof vd->ecp.tx.frame);
	ecp_append(vd->ecp.tx.frame, &fb_offset, (void *)&eth, sizeof eth);

	ecp_hdr.oui[0] = 0x0;
	ecp_hdr.oui[1] = 0x1b;
	ecp_hdr.oui[2] = 0x3f;
	ecp_hdr.pad1 = 0x0;
	ecp_hdr.subtype = ECP_SUBTYPE;
	ecp_hdr.mode = ECP_REQUEST;

	vd->ecp.lastSequence++;
	ecp_hdr.seqnr = htons(vd->ecp.lastSequence);
	ecp_append(vd->ecp.tx.frame, &fb_offset, (void *)&ecp_hdr,
		   sizeof ecp_hdr);

	/* create packed_tlvs for all profiles on this interface */
	LIST_FOREACH(p, &vd->profile_head, profile) {

		if (!p->localChange) {
			LLDPAD_DBG("%s:%s skipping unchanged profile\n",
				   __func__, vd->ecp.ifname);
			continue;
		}

		ptlv = vdp_gettlv(vd, p);

		if (!ptlv) {
			LLDPAD_DBG("%s:%s ptlv not created\n", __func__,
				   vd->ecp.ifname);
			continue;
		}

		rc = ecp_append(vd->ecp.tx.frame, &fb_offset, ptlv->tlv,
				ptlv->size);
		ptlv = free_pkd_tlv(ptlv);
		if (rc)
			p->seqnr = vd->ecp.lastSequence;
		else
			break;
	}
	ecp_append(vd->ecp.tx.frame, &fb_offset, end_tlv, sizeof end_tlv);
	vd->ecp.tx.frame_len = MAX(fb_offset, (unsigned)ETH_ZLEN);
	return true;
}

/* ecp_tx_Initialize - initializes the ecp tx state machine
 * @vd: currently used port
 *
 * no return value
 *
 * initializes some variables for the ecp tx state machine.
 */
static void ecp_tx_Initialize(struct vdp_data *vd)
{
	memset(vd->ecp.tx.frame, 0, sizeof vd->ecp.tx.frame);
	ecp_somethingChangedLocal(vd, true);
	vd->ecp.lastSequence = ECP_SEQUENCE_NR_START;
	vd->ecp.stats.statsFramesOutTotal = 0;
	vd->ecp.ackTimer = ECP_ACK_TIMER_STOPPED;
	vd->ecp.retries = 0;
}

/* ecp_txFrame - transmit ecp frame
 * @vd: currently used port
 *
 * returns the number of characters sent on success, -1 on failure
 *
 * sends out the frame stored in the frame structure using l2_packet_send.
 */
static u8 ecp_txFrame(struct vdp_data *vd)
{
	int status = 0;

	status = l2_packet_send(vd->ecp.l2, (u8 *)&nearest_bridge,
		htons(ETH_P_ECP), vd->ecp.tx.frame, vd->ecp.tx.frame_len);
	vd->ecp.stats.statsFramesOutTotal++;
	vd->ecp.tx.frame_len = 0;
	return status;
}

/* ecp_tx_create_frame - create ecp frame
 * @vd: currently used port
 *
 * no return value
 */
static void ecp_tx_create_frame(struct vdp_data *vd)
{
	/* send REQs */
	if (vd->ecp.tx.localChange) {
		int ret;

		LLDPAD_DBG("%s:%s sending REQs\n", __func__, vd->ecp.ifname);
		ret = ecp_build_ECPDU(vd);

		/* ECPDU construction succesful, send out frame */
		if (ret == true) {
			hexdump_frame(vd->ecp.ifname, "frame-out",
				      vd->ecp.tx.frame, vd->ecp.tx.frame_len);
			ecp_txFrame(vd);
		}
	}

	ecp_somethingChangedLocal(vd, false);
}

/* ecp_tx_start_ackTimer - starts the ECP ack timer
 * @vd: vdp_data to process
 *
 * returns 0 on success, -1 on error
 *
 * starts the ack timer when a frame has been sent out.
 */
static void ecp_tx_start_ackTimer(struct vdp_data *vd)
{
	vd->ecp.ackTimer = ECP_ACK_TIMER_DEFAULT;
	LLDPAD_DBG("%s-%s: starting ecp ack timer\n", __func__, vd->ifname);
	ecp_start_ack_timer(vd);
}

/* ecp_tx_change_state - changes the ecp tx sm state
 * @vd: currently used port
 * @newstate: new state for the sm
 *
 * no return value
 *
 * checks state transistion for consistency and finally changes the state of
 * the profile.
 */
static void ecp_tx_change_state(struct vdp_data *vd, u8 newstate)
{
	switch(newstate) {
	case ECP_TX_INIT_TRANSMIT:
		break;
	case ECP_TX_TRANSMIT_ECPDU:
		assert((vd->ecp.tx.state == ECP_TX_INIT_TRANSMIT) ||
		       (vd->ecp.tx.state == ECP_TX_WAIT_FOR_ACK) ||
		       (vd->ecp.tx.state == ECP_TX_REQUEST_PDU));
		break;
	case ECP_TX_WAIT_FOR_ACK:
		assert(vd->ecp.tx.state == ECP_TX_TRANSMIT_ECPDU);
		break;
	case ECP_TX_REQUEST_PDU:
		assert(vd->ecp.tx.state == ECP_TX_WAIT_FOR_ACK);
		break;
	default:
		LLDPAD_ERR("%s: LLDP TX state machine invalid state %d\n",
			   vd->ifname, newstate);
	}
	LLDPAD_DBG("%s-%s: state change %s -> %s\n", __func__,
		   vd->ifname, ecp_tx_states[vd->ecp.tx.state],
		   ecp_tx_states[newstate]);
	vd->ecp.tx.state = newstate;
	return;
}

/* ecp_set_tx_state - sets the ecp tx sm state
 * @vd: currently used port
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool ecp_set_tx_state(struct vdp_data *vd)
{
	struct port *port = port_find_by_name(vd->ifname);

	if (!port) {
		LLDPAD_ERR("%s: port not found\n", __func__);
		return 0;
	}

	if ((port->portEnabled == false) && (port->prevPortEnabled == true)) {
		LLDPAD_ERR("set_tx_state: port was disabled\n");
		ecp_tx_change_state(vd, ECP_TX_INIT_TRANSMIT);
	}
	port->prevPortEnabled = port->portEnabled;

	switch (vd->ecp.tx.state) {
	case ECP_TX_INIT_TRANSMIT:
		if (port->portEnabled && (vd->enabletx == true)
					  && vd->ecp.tx.localChange) {
			ecp_tx_change_state(vd, ECP_TX_TRANSMIT_ECPDU);
			return true;
		}
		return false;
	case ECP_TX_TRANSMIT_ECPDU:
		if (vd->enabletx == false) {
			ecp_tx_change_state(vd, ECP_TX_INIT_TRANSMIT);
			return true;
		}
		ecp_tx_change_state(vd, ECP_TX_WAIT_FOR_ACK);
		return false;
	case ECP_TX_WAIT_FOR_ACK:
		if (ecp_ackTimer_expired(vd)) {
			vd->ecp.retries++;
			if (vd->ecp.retries < ECP_MAX_RETRIES) {
				ecp_somethingChangedLocal(vd, true);
				ecp_tx_change_state(vd, ECP_TX_TRANSMIT_ECPDU);
				return true;
			}
			if (vd->ecp.retries == ECP_MAX_RETRIES) {
				LLDPAD_DBG("%s-%s: retries expired\n",
					   __func__, vd->ifname);
				ecp_tx_stop_ackTimer(vd);
				ecp_tx_change_state(vd, ECP_TX_REQUEST_PDU);
				return true;
			}
		}
		if (vd->ecp.ackReceived &&
		    vd->ecp.seqECPDU == vd->ecp.lastSequence) {
			vd->ecp.ackReceived = false;
			if (vdp_vsis_pending(vd)) {
				LLDPAD_DBG("%s-%s: still work pending\n",
					   __func__, vd->ifname);
				ecp_somethingChangedLocal(vd, true);
			}
			ecp_tx_change_state(vd, ECP_TX_REQUEST_PDU);
			return true;
		}
		return false;
	case ECP_TX_REQUEST_PDU:
		if (vd->ecp.tx.localChange) {
			ecp_tx_change_state(vd, ECP_TX_TRANSMIT_ECPDU);
			return true;
		}
		return false;
	default:
		LLDPAD_ERR("%s: LLDP TX state machine in invalid state %d\n",
			   vd->ifname, vd->ecp.tx.state);
		return false;
	}
}

/* ecp_tx_run_sm - state machine for ecp tx
 * @vd: currently used vdp_data
 *
 * no return value
 *
 * runs the state machine for ecp tx.
 */
void ecp_tx_run_sm(struct vdp_data *vd)
{
	do {
		LLDPAD_DBG("%s-%s: ecp_tx - %s\n", __func__,
		       vd->ifname, ecp_tx_states[vd->ecp.tx.state]);

		switch(vd->ecp.tx.state) {
		case ECP_TX_INIT_TRANSMIT:
			ecp_tx_Initialize(vd);
			break;
		case ECP_TX_TRANSMIT_ECPDU:
			ecp_tx_create_frame(vd);
			ecp_tx_start_ackTimer(vd);
			ecp_somethingChangedLocal(vd, false);
			break;
		case ECP_TX_WAIT_FOR_ACK:
			if (vd->ecp.ackReceived) {
				LLDPAD_DBG("%s-%s: ECP_TX_WAIT_FOR_ACK "
					   "ackReceived seqECPDU %#x "
					   "lastSequence %#x\n", __func__,
					   vd->ifname, vd->ecp.seqECPDU,
					   vd->ecp.lastSequence);
				ecp_somethingChangedLocal(vd, false);
				ecp_tx_stop_ackTimer(vd);
			}
			break;
		case ECP_TX_REQUEST_PDU:
			vd->ecp.retries = 0;
			LLDPAD_DBG("%s-%s: ECP_TX_REQUEST_PDU lastSeq %#x\n",
				   __func__, vd->ifname, vd->ecp.lastSequence);
			break;
		default:
			LLDPAD_ERR("%s: LLDP TX state machine in invalid state %d\n",
				   vd->ifname, vd->ecp.tx.state);
		}
	} while (ecp_set_tx_state(vd) == true);
}

static const char *ecp_rx_states[] = {
	"ECP_RX_IDLE",
	"ECP_RX_INIT_RECEIVE",
	"ECP_RX_RECEIVE_WAIT",
	"ECP_RX_RECEIVE_ECPDU",
	"ECP_RX_SEND_ACK",
	"ECP_RX_RESEND_ACK",
};

/* ecp_rx_Initialize - initializes the ecp rx state machine
 * @vd: vd for the state machine
 *
 * no return value
 *
 * initialize some variables, get rid of old frame if necessary
 */
static void ecp_rx_Initialize(struct vdp_data *vd)
{
	vd->ecp.rx.rcvFrame = false;
	vd->ecp.ackReceived = false;
	vd->ecp.rx.frame_len = 0;
}

/* ecp_rx_SendAckFrame - send ack frame
 * @vd: port used by ecp
 *
 * currently always returns 0
 *
 * copies current received frame over to frame out, fills in address of this
 * port and set mode field to ACK. used by ecp_rx_send_ack_frame.
 */
static int ecp_rx_SendAckFrame(struct vdp_data *vd)
{
	u16 tlv_offset = 0;
	struct ecp_hdr *ecp_hdr;
	struct l2_ethhdr *hdr;
	u8 own_addr[ETH_ALEN];

	LLDPAD_DBG("%s:%s acking frame\n", __func__, vd->ecp.ifname);
	/* copy over to transmit buffer */
	memcpy(vd->ecp.tx.frame, vd->ecp.rx.frame, vd->ecp.rx.frame_len);
	vd->ecp.tx.frame_len = vd->ecp.rx.frame_len;

	/* use my own addr to send ACK */
	hdr = (struct l2_ethhdr *)vd->ecp.tx.frame;
	l2_packet_get_own_src_addr(vd->ecp.l2,(u8 *)&own_addr);
	memcpy(hdr->h_source, &own_addr, ETH_ALEN);

	tlv_offset = sizeof(struct l2_ethhdr);
	ecp_hdr = (struct ecp_hdr *)&vd->ecp.tx.frame[tlv_offset];
	ecp_hdr->mode = ECP_ACK;

	tlv_offset = sizeof(struct l2_ethhdr) + sizeof(struct ecp_hdr);
	LLDPAD_DBG("%s:%s zeroing out rest of ack frame from %i to %i\n",
		   __func__, vd->ecp.ifname, tlv_offset, vd->ecp.rx.frame_len);
	memset(&vd->ecp.tx.frame[tlv_offset], 0,
	       vd->ecp.rx.frame_len - tlv_offset);
	return 0;
}

/* ecp_rx_send_ack_frame - send out ack frame for received frame
 * @vd: vd for the state machine
 *
 * no return value
 *
 * creates an ack frame for a just received frame, prints the about to be
 * sent frame and finally transmits it.
 */
void ecp_rx_send_ack_frame(struct vdp_data *vd)
{
	ecp_rx_SendAckFrame(vd);
	hexdump_frame(vd->ecp.ifname, "frame-ack", vd->ecp.tx.frame,
		      vd->ecp.tx.frame_len);
	ecp_txFrame(vd);
}

/* ecp_rx_ReceiveFrame - receive ecp frame
 * @ctx: rx callback context, struct vd * in this case
 * @ifindex: index of interface
 * @buf: buffer which contains the frame just received
 * @len: size of buffer (frame)
 *
 * no return value
 *
 * creates a local copy of the buffer and checks the header. keeps some
 * statistics about ecp frames. Checks if it is a request or an ack frame
 * and branches to ecp rx or ecp tx state machine.
 */
static void ecp_rx_ReceiveFrame(void *ctx, UNUSED int ifindex, const u8 *buf,
				size_t len)
{
	struct vdp_data *vd;
	struct port *port;
	u8  frame_error = 0;
	u16 tlv_offset;
	struct l2_ethhdr *hdr;
	struct l2_ethhdr example_hdr,*ex;
	struct ecp_hdr *ecp_hdr;

	if (!ctx) {
		LLDPAD_WARN("%s: no ctx - can't process frame\n", __func__);
		return;
	}

	vd = (struct vdp_data *)ctx;
	port = port_find_by_name(vd->ifname);
	if (port == NULL)
		return;

	LLDPAD_DBG("%s:%s received packet with size %i\n", __func__,
		   vd->ecp.ifname, (int)len);
	if (vd->enabletx == false)
		return;

	if (vd->ecp.rx.frame_len == len &&
	    (memcmp(buf, vd->ecp.rx.frame, len) == 0)) {
		vd->ecp.stats.statsFramesInTotal++;
		return;
	}

	memset(vd->ecp.rx.frame, 0, len);
	memcpy(vd->ecp.rx.frame, buf, len);

	vd->ecp.rx.frame_len = (u16)len;
	ex = &example_hdr;
	memcpy(ex->h_dest, nearest_bridge, ETH_ALEN);
	ex->h_proto = htons(ETH_P_ECP);
	hdr = (struct l2_ethhdr *)vd->ecp.rx.frame;

	if ((memcmp(hdr->h_dest, ex->h_dest, ETH_ALEN) != 0)) {
		LLDPAD_ERR("%s:%s ERROR multicast address error in incoming frame."
			   " Dropping frame.\n", __func__, vd->ecp.ifname);
		frame_error++;
		return;
	}

	if (hdr->h_proto != example_hdr.h_proto) {
		LLDPAD_ERR("%s:%s ERROR ethertype %#x not ECP ethertype",
			    __func__, vd->ecp.ifname, htons(hdr->h_proto));
		frame_error++;
		return;
	}

	if (!frame_error) {
		vd->ecp.stats.statsFramesInTotal++;
		vd->ecp.rx.rcvFrame = true;
	}

	tlv_offset = sizeof(struct l2_ethhdr);
	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.frame[tlv_offset];
	vd->ecp.seqECPDU = ntohs(ecp_hdr->seqnr);
	hexdump_frame(vd->ecp.ifname, "frame-in", vd->ecp.rx.frame,
		      vd->ecp.rx.frame_len);

	switch(ecp_hdr->mode) {
	case ECP_REQUEST:
		LLDPAD_DBG("%s:%s received REQ frame\n", __func__,
			   vd->ecp.ifname);
		vd->ecp.ackReceived = false;
		ecp_rx_run_sm(vd);
		break;
	case ECP_ACK:
		LLDPAD_DBG("%s:%s received ACK frame\n", __func__,
			   vd->ecp.ifname);
		vd->ecp.ackReceived = true;
		vdp_ack_profiles(vd, vd->ecp.seqECPDU);
		ecp_tx_run_sm(vd);
		vd->ecp.ackReceived = false;
		break;
	default:
		LLDPAD_ERR("%s:%s ERROR: unknown mode %i\n", __func__,
			   vd->ecp.ifname, ecp_hdr->mode);
		return;
	}

}

/* ecp_rx_change_state - changes the ecp rx sm state
 * @vd: currently used port
 * @newstate: new state for the sm
 *
 * no return value
 *
 * checks state transistion for consistency and finally changes the state of
 * the profile.
 */
static void ecp_rx_change_state(struct vdp_data *vd, u8 newstate)
{
	switch(newstate) {
	case ECP_RX_IDLE:
		break;
	case ECP_RX_INIT_RECEIVE:
		break;
	case ECP_RX_RECEIVE_WAIT:
		assert((vd->ecp.rx.state == ECP_RX_INIT_RECEIVE) ||
		       (vd->ecp.rx.state == ECP_RX_IDLE) ||
		       (vd->ecp.rx.state == ECP_RX_SEND_ACK) ||
		       (vd->ecp.rx.state == ECP_RX_RESEND_ACK));
		break;
	case ECP_RX_RECEIVE_ECPDU:
		assert(vd->ecp.rx.state == ECP_RX_RECEIVE_WAIT);
		break;
	case ECP_RX_SEND_ACK:
		assert(vd->ecp.rx.state == ECP_RX_RECEIVE_ECPDU);
		break;
	case ECP_RX_RESEND_ACK:
		assert(vd->ecp.rx.state == ECP_RX_RECEIVE_ECPDU);
		break;
	default:
		LLDPAD_ERR("%s:%s LLDP RX state machine invalid state %d\n",
			   __func__, vd->ecp.ifname, newstate);
	}

	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   vd->ecp.ifname, ecp_rx_states[vd->ecp.rx.state],
		   ecp_rx_states[newstate]);

	vd->ecp.rx.state = newstate;
}

/* ecp_init - initialize ecp module
 * @ifname: interface for which the module is initialized
 *
 * returns 0 on success, -1 on error
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming ecp frames and initializes the ecp rx and tx state machines.
 * should usually be called when a successful exchange of EVB TLVs has been
 * made and ECP and VDP protocols are supported by both sides.
 */
int ecp_init(char *ifname)
{
	struct vdp_data *vd;

	LLDPAD_DBG("%s:%s starting ECP\n", __func__, ifname);
	vd = vdp_data(ifname);
	if (!vd) {
		LLDPAD_ERR("%s:%s unable to find vd\n", __func__, ifname);
		return -1;
	}

	if (!vd->ecp.l2)
		vd->ecp.l2 = l2_packet_init(vd->ifname, NULL, ETH_P_ECP,
					    ecp_rx_ReceiveFrame, vd, 1);

	if (!vd->ecp.l2) {
		LLDPAD_ERR("%s:%s failed to access layer 2 access ETH_P_ECP\n",
			   __func__, ifname);
		return -1;
	}
	strncpy(vd->ecp.ifname, ifname, sizeof vd->ecp.ifname);
	ecp_rx_change_state(vd, ECP_RX_IDLE);
	ecp_rx_run_sm(vd);
	ecp_somethingChangedLocal(vd, true);
	return 0;
}

/* ecp_rx_validate_frame - validates received frame
 * @vd: vdp_data used by ecp
 *
 * no return value
 *
 * checks wether received frame has correct subtype and mode
 */

static void ecp_rx_validate_frame(struct vdp_data *vd)
{
	u16 tlv_offset = 0;
	struct ecp_hdr *ecp_hdr;

	LLDPAD_DBG("%s:%s validating frame\n", __func__, vd->ecp.ifname);
	tlv_offset = sizeof(struct l2_ethhdr);
	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.frame[tlv_offset];
	LLDPAD_DBG("%s:%s ecp packet with subtype %#x mode %#x seq %#04x\n",
		   __func__, vd->ecp.ifname, ecp_hdr->subtype, ecp_hdr->mode,
		   ntohs(ecp_hdr->seqnr));

	if (ecp_hdr->subtype != ECP_SUBTYPE) {
		LLDPAD_ERR("%s:%s ERROR: unknown subtype\n", __func__,
			   vd->ecp.ifname);
		return;
	}

	if ((ecp_hdr->oui[0] != 0x0) || (ecp_hdr->oui[1] != 0x1b) ||
		(ecp_hdr->oui[2] != 0x3f)) {
		LLDPAD_ERR("%s:%s ERROR: incorrect OUI 0x%02x%02x%02x\n",
			   __func__, vd->ecp.ifname, ecp_hdr->oui[0],
			   ecp_hdr->oui[1], ecp_hdr->oui[2]);
		return;
	}

	switch(ecp_hdr->mode) {
	case ECP_REQUEST:
		break;
	case ECP_ACK:
		break;
	default:
		LLDPAD_ERR("%s:%s ERROR: unknown mode %i\n", __func__,
			   vd->ecp.ifname, ecp_hdr->mode);
		return;
	}

	/* FIXME: also done in ecp_rx_ReceiveFrame,
	 * are both necessary ? */
	vd->ecp.seqECPDU = ntohs(ecp_hdr->seqnr);
}

/* ecp_rx_ProcessFrame - process received ecp frames
 * @vd: currently used port
 *
 * no return value
 *
 * walks through the packed vsi tlvs in an ecp frame, extracts them
 * and passes them to the VDP ULP with vdp_indicate.
 */
static void ecp_rx_ProcessFrame(struct vdp_data *vd)
{
	u16 tlv_cnt = 0;
	u8  tlv_type = 0;
	u16 tlv_length = 0;
	u16 tlv_offset = 0;
	u16 *tlv_head_ptr = NULL;
	u8  frame_error = 0;
	bool tlv_stored = false;
	struct ecp_hdr *ecp_hdr;
	int vdp_called;

	LLDPAD_DBG("%s:%s processing frame\n", __func__, vd->ecp.ifname);
	tlv_offset = sizeof(struct l2_ethhdr);

	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.frame[tlv_offset];
	LLDPAD_DBG("%s:%s ecp packet with subtype %#x mode %#x seq %#04x\n",
		   __func__, vd->ifname, ecp_hdr->subtype,
		   ecp_hdr->mode, ntohs(ecp_hdr->seqnr));
	if (ecp_hdr->mode == ECP_ACK)
		return;

	/* processing of VSI_TLVs starts here */
	tlv_offset += sizeof(struct ecp_hdr);
	vdp_called = 0;
	do {
		tlv_cnt++;

		if (tlv_offset > vd->ecp.rx.frame_len) {
			LLDPAD_ERR("%s:%s ERROR: Frame overrun! tlv_offset %i"
				   " frame_len %i cnt %i\n", __func__,
				   vd->ecp.ifname, tlv_offset,
				   vd->ecp.rx.frame_len, tlv_cnt);
			frame_error++;
			goto out;
		}

		if (tlv_offset + 2 > vd->ecp.rx.frame_len) {
			LLDPAD_DBG("%s:%s tlv EOF problem size=%d offset=%d\n",
				   __func__, vd->ecp.ifname,
				   vd->ecp.rx.frame_len, tlv_offset);
			frame_error++;
			goto out;
		}

		tlv_head_ptr = (u16 *)&vd->ecp.rx.frame[tlv_offset];
		tlv_length = htons(*tlv_head_ptr) & 0x01FF;
		tlv_type = (u8)(htons(*tlv_head_ptr) >> 9);

		u16 tmp_offset = tlv_offset + tlv_length;
		if (tmp_offset > vd->ecp.rx.frame_len) {
			LLDPAD_ERR("%s:%s ERROR: Frame overflow: offset=%d "
				   "rx.size=%d\n", __func__, vd->ecp.ifname,
				   tmp_offset, vd->ecp.rx.frame_len);
			frame_error++;
			goto out;
		}

		u8 *info = (u8 *)&vd->ecp.rx.frame[tlv_offset +
					sizeof(*tlv_head_ptr)];

		struct unpacked_tlv *tlv = create_tlv();

		if (!tlv) {
			LLDPAD_DBG("%s:%s failed malloc for incoming TLV\n",
				   __func__, vd->ecp.ifname);
			goto out;
		}

		if ((tlv_length == 0) && (tlv->type != TYPE_0)) {
			LLDPAD_DBG("%s:%s tlv_length == 0\n", __func__,
				   vd->ecp.ifname);
			free_unpkd_tlv(tlv);
			goto out;
		}

		tlv->type = tlv_type;
		tlv->length = tlv_length;
		tlv->info = (u8 *)malloc(tlv_length);
		if (tlv->info) {
			memset(tlv->info,0, tlv_length);
			memcpy(tlv->info, info, tlv_length);
		} else {
			LLDPAD_DBG("%s:%s failed malloc for incoming TLV info\n",
				   __func__, vd->ecp.ifname);
			free_unpkd_tlv(tlv);
			goto out;
		}

		/* Validate the TLV */
		tlv_offset += sizeof(*tlv_head_ptr) + tlv_length;

		if (tlv->type == TYPE_127) { /* private TLV */
			/* give VSI TLV to VDP */
			if (!vdp_indicate(vd, tlv)) {
				tlv_stored = true;
				++vdp_called;
			} else {
				/* TODO
				 * put it in a list and try again later until
				 * timer and retries have expired
				 */
				tlv_stored = false;
			}
		}

		if ((tlv->type != TYPE_0) && !tlv_stored) {
			LLDPAD_DBG("%s:%s TLV (%u) was not stored (%p)\n",
				   __func__, vd->ecp.ifname, tlv->type, tlv);
			tlv = free_unpkd_tlv(tlv);
			vd->ecp.stats.statsTLVsUnrecognizedTotal++;
		}
		tlv = NULL;
		tlv_stored = false;
	} while (tlv_offset < vd->ecp.rx.frame_len);
out:
	if (frame_error) {
		vd->ecp.stats.statsFramesDiscardedTotal++;
		vd->ecp.stats.statsFramesInErrorsTotal++;
	}
	if (vdp_called)
		vdp_advance_sm(vd);
}

/* ecp_set_rx_state - sets the ecp rx sm state
 * @vd: currently used port
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool ecp_set_rx_state(struct vdp_data *vd)
{
	struct port *port = port_find_by_name(vd->ifname);

	if (!port)
		return false;

	if (port->portEnabled == false)
		ecp_rx_change_state(vd, ECP_RX_IDLE);

	switch(vd->ecp.rx.state) {
	case ECP_RX_IDLE:
		if (port->portEnabled == true) {
			ecp_rx_change_state(vd, ECP_RX_INIT_RECEIVE);
			return true;
		}
		return false;
	case ECP_RX_INIT_RECEIVE:
		if (vd->enabletx == true) {
			ecp_rx_change_state(vd, ECP_RX_RECEIVE_WAIT);
			return true;
		}
		return false;
	case ECP_RX_RECEIVE_WAIT:
		if (vd->enabletx == false) {
			ecp_rx_change_state(vd, ECP_RX_IDLE);
			return true;
		}
		if (vd->ecp.rx.rcvFrame == true) {
			ecp_rx_change_state(vd, ECP_RX_RECEIVE_ECPDU);
			return true;
		}
		return false;
	case ECP_RX_RECEIVE_ECPDU:
		if (vd->ecp.seqECPDU == vd->ecp.lastSequence) {
			LLDPAD_DBG("%s:%s seqECPDU %x, lastSequence %x\n",
				   __func__, vd->ecp.ifname, vd->ecp.seqECPDU,
				   vd->ecp.lastSequence);
			ecp_rx_change_state(vd, ECP_RX_RESEND_ACK);
			return true;
		}
		if (vd->ecp.seqECPDU != vd->ecp.lastSequence) {
			ecp_rx_change_state(vd, ECP_RX_RESEND_ACK);
			return true;
		}
		return false;
	case ECP_RX_SEND_ACK:
	case ECP_RX_RESEND_ACK:
		ecp_rx_change_state(vd, ECP_RX_RECEIVE_WAIT);
		return false;
	default:
		LLDPAD_DBG("%s:%s ECP RX state machine in invalid state %d\n",
			   __func__, vd->ecp.ifname, vd->ecp.rx.state);
		return false;
	}
}

/* ecp_rx_run_sm - state machine for ecp rx
 * @vd: currently used port
 *
 * no return value
 *
 * runs the state machine for ecp rx.
 */
static void ecp_rx_run_sm(struct vdp_data *vd)
{
	ecp_set_rx_state(vd);
	do {
		LLDPAD_DBG("%s:%s ecp_rx - %s\n", __func__, vd->ecp.ifname,
			   ecp_rx_states[vd->ecp.tx.state]);

		switch(vd->ecp.rx.state) {
		case ECP_RX_IDLE:
			break;
		case ECP_RX_INIT_RECEIVE:
			ecp_rx_Initialize(vd);
			break;
		case ECP_RX_RECEIVE_WAIT:
			break;
		case ECP_RX_RECEIVE_ECPDU:
			vd->ecp.rx.rcvFrame = false;
			ecp_rx_validate_frame(vd);
			break;
		case ECP_RX_SEND_ACK:
			ecp_rx_ProcessFrame(vd);
			break;
		case ECP_RX_RESEND_ACK:
			ecp_rx_ProcessFrame(vd);
			if (!vd->ecp.ackReceived) {
				ecp_rx_send_ack_frame(vd);
			}
			break;
		default:
			LLDPAD_DBG("%s:%s ECP RX state machine in invalid state %d\n",
				   __func__, vd->ecp.ifname, vd->ecp.rx.state);
		}
	} while (ecp_set_rx_state(vd) == true);
}
