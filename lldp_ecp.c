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
#include "lldp_vdp.h"
#include "messages.h"
#include "config.h"
#include "lldp/l2_packet.h"

#include "lldp_tlv.h"

/*
 * ecp_print_frame - print raw ecp frame
 */
void ecp_print_frame(char *ifname, char *txt, u8 *buf, u32 len)
{
	u32 i, left = 0;
	char buffer[ETH_FRAME_LEN * 3];

	for (i = 0; i < len; i++) {
		int c;
		c = snprintf(buffer + left, sizeof buffer - left, "%02x%c",
			     buf[i], !((i + 1) % 16) ? '\n' : ' ');
		if (c > 0 && (c < (int)sizeof buffer - (int)left))
			left += c;
	}
	LLDPAD_DBG("%s:%s %s\n%s\n", __func__, ifname, txt, buffer);
}

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
int ecp_start_localchange_timer(struct vdp_data *vd)
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
int ecp_start_ack_timer(struct vdp_data *vd)
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
int ecp_stop_ack_timer(struct vdp_data *vd)
{
	LLDPAD_DBG("%s:%s stopping ecp ack timer\n", __func__, vd->ecp.ifname);
	return eloop_cancel_timeout(ecp_ack_timeout_handler, NULL, (void *) vd);
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
bool ecp_build_ECPDU(struct vdp_data *vd)
{
	struct l2_ethhdr eth;
	struct ecp_hdr ecp_hdr;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	struct packed_tlv *ptlv =  NULL;
	struct vsi_profile *p;

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

		if (ptlv) {
			if (!ecp_append(vd->ecp.tx.frame, &fb_offset,
				       ptlv->tlv, ptlv->size))
				ptlv = free_pkd_tlv(ptlv);
				break;
		}

		p->seqnr = vd->ecp.lastSequence;

		ptlv = free_pkd_tlv(ptlv);
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
	struct port *port = port_find_by_name(vd->ifname);

	if (!port)
		return;

	memset(vd->ecp.tx.frame, 0, sizeof vd->ecp.tx.frame);
	ecp_somethingChangedLocal(vd, true);
	vd->ecp.lastSequence = ECP_SEQUENCE_NR_START;
	vd->ecp.stats.statsFramesOutTotal = 0;
	vd->ecp.ackTimer = ECP_ACK_TIMER_STOPPED;
	vd->ecp.retries = 0;

	l2_packet_get_port_state(vd->ecp.l2, (u8 *)&(port->portEnabled));
}

/* ecp_txFrame - transmit ecp frame
 * @vd: currently used port
 *
 * returns the number of characters sent on success, -1 on failure
 *
 * sends out the frame stored in the frame structure using l2_packet_send.
 */
u8 ecp_txFrame(struct vdp_data *vd)
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
			ecp_print_frame(vd->ecp.ifname, "frame-out",
					vd->ecp.tx.frame,
					vd->ecp.tx.frame_len);
			ecp_txFrame(vd);
		}
	}

	ecp_somethingChangedLocal(vd, false);
}

/* ecp_tx_stop_ackTimer - stop the ECP ack timer
 * @vd: currently used port
 *
 * returns the number of removed handlers
 *
 * stops the ECP ack timer. used when a ack frame for the port has been
 * received.
 */
void ecp_tx_stop_ackTimer(struct vdp_data *vd)
{
	vd->ecp.ackTimer = ECP_ACK_TIMER_STOPPED;

	LLDPAD_DBG("%s:%s stopped ecp ack timer\n", __func__, vd->ecp.ifname);

	ecp_stop_ack_timer(vd);
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

/* ecp_ackTimer_expired - checks for expired ack timer
 * @vd: vdp_data for interface
 *
 * returns true or false
 *
 * returns true if ack timer has expired, false otherwise.
 */
bool ecp_ackTimer_expired(struct vdp_data *vd)
{
	return (vd->ecp.ackTimer == 0);
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
