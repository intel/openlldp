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

*******************************************************************************/

#include <stdio.h>
#include <assert.h>
#include "lldp/ports.h"
#include "lldp/l2_packet.h"
#include "messages.h"
#include "lldp.h"
#include "lldp_tlv.h"
#include "lldpad.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp_mand.h"
#include "lldp_vdp.h"
#include "ecp.h"

static const char *ecp_rx_states[] = {
	"ECP_RX_IDLE",
	"ECP_RX_INIT_RECEIVE",
	"ECP_RX_RECEIVE_WAIT",
	"ECP_RX_RECEIVE_ECPDU",
	"ECP_RX_SEND_ACK",
	"ECP_RX_RESEND_ACK",
};

/* ecp_rx_freeFrame - free up received frame
 * @vd: vd for the state machine
 *
 * no return value
 *
 * frees up an old received frame, set pointer to NULL and size to 0.
 */
static void ecp_rx_freeFramein(struct vdp_data *vd)
{
	if (vd->ecp.rx.framein)
		free(vd->ecp.rx.framein);
	vd->ecp.rx.framein = NULL;
	vd->ecp.rx.sizein = 0;
}

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
	vd->ecp.rx.badFrame = false;
	vd->ecp.ackReceived = false;
	ecp_rx_freeFramein(vd);
}

/* ecp_print_framein - print raw received frame
 * @vd: vd for the state machine
 *
 * no return value
 *
 * prints out a raw version of a received frame. useful for low-level protocol
 * debugging.
 */
static void ecp_print_framein(struct vdp_data *vd)
{
	int i, left = 0;
	char buffer[128];

	for (i = 0; i < vd->ecp.rx.sizein; i++) {
		int c;
		c = snprintf(buffer + left, sizeof buffer - left, "%02x ",
			     vd->ecp.rx.framein[i]);
		if (c > 0 && (c < (int)sizeof buffer - left))
			left += c;
		if (!((i+1) % 16)) {
			LLDPAD_DBG("%s\n", buffer);
			left = 0;
		}
	}
	LLDPAD_DBG("%s\n", buffer);
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

	LLDPAD_DBG("%s-%s: acking frame\n", __func__, vd->ifname);

	assert(vd->ecp.rx.framein && vd->ecp.rx.sizein);

	/* copy over to frameout */
	vd->ecp.tx.frameout = (u8 *)malloc(ETH_FRAME_LEN);
	memcpy(vd->ecp.tx.frameout, vd->ecp.rx.framein, vd->ecp.rx.sizein);
	vd->ecp.tx.sizeout = vd->ecp.rx.sizein;

	/* use my own addr to send ACK */
	hdr = (struct l2_ethhdr *)vd->ecp.tx.frameout;
	l2_packet_get_own_src_addr(vd->ecp.l2,(u8 *)&own_addr);
	memcpy(hdr->h_source, &own_addr, ETH_ALEN);

	tlv_offset = sizeof(struct l2_ethhdr);
	ecp_hdr = (struct ecp_hdr *)&vd->ecp.tx.frameout[tlv_offset];
	ecp_hdr->mode = ECP_ACK;

	tlv_offset = sizeof(struct l2_ethhdr) + sizeof(struct ecp_hdr);
	LLDPAD_DBG("%s-%s: zeroing out rest of ack frame from %i to %i\n",
		   __func__, vd->ifname, tlv_offset, vd->ecp.rx.sizein);
	memset(&vd->ecp.tx.frameout[tlv_offset], 0,
	       vd->ecp.rx.sizein-tlv_offset);
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
	ecp_print_frameout(vd);
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
 * statistics about ecp frames. Checks if it is a request or an ack frame and branches
 * to ecp rx or ecp tx state machine.
 */
void
ecp_rx_ReceiveFrame(void *ctx, UNUSED int ifindex, const u8 *buf, size_t len)
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

	LLDPAD_DBG("%s-%s: received packet with size %i\n",
		   __func__, vd->ifname, (int) len);

	if (vd->enabletx == false)
		return;

	if (vd->ecp.rx.framein &&
	    vd->ecp.rx.sizein == len &&
	    (memcmp(buf, vd->ecp.rx.framein, len) == 0)) {
		vd->ecp.stats.statsFramesInTotal++;
		return;
	}

	if (vd->ecp.rx.framein)
		free(vd->ecp.rx.framein);

	vd->ecp.rx.framein = (u8 *)malloc(len);
	if (vd->ecp.rx.framein == NULL) {
		LLDPAD_ERR("ERROR - allocating memory for rx'ed frame\n");
		return;
	}
	memset(vd->ecp.rx.framein, 0, len);
	memcpy(vd->ecp.rx.framein, buf, len);

	vd->ecp.rx.sizein = (u16)len;
	ex = &example_hdr;
	memcpy(ex->h_dest, nearest_bridge, ETH_ALEN);
	ex->h_proto = htons(ETH_P_ECP);
	hdr = (struct l2_ethhdr *)vd->ecp.rx.framein;

	if ((memcmp(hdr->h_dest,ex->h_dest, ETH_ALEN) != 0)) {
		LLDPAD_ERR("ERROR multicast address error in incoming frame. "
			"Dropping frame.\n");
		frame_error++;
		ecp_rx_freeFramein(vd);
		return;
	}

	if (hdr->h_proto != example_hdr.h_proto) {
		LLDPAD_ERR("ERROR Ethertype not ECP ethertype but ethertype "
			"'%x' in incoming frame.\n", htons(hdr->h_proto));
		frame_error++;
		ecp_rx_freeFramein(vd);
		return;
	}

	if (!frame_error) {
		vd->ecp.stats.statsFramesInTotal++;
		vd->ecp.rx.rcvFrame = 1;
	}

	tlv_offset = sizeof(struct l2_ethhdr);

	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.framein[tlv_offset];

	vd->ecp.seqECPDU = ntohs(ecp_hdr->seqnr);

	ecp_print_framein(vd);

	switch(ecp_hdr->mode) {
	case ECP_REQUEST:
		LLDPAD_DBG("%s-%s: received REQ frame\n",
			   __func__, vd->ifname);
		vd->ecp.ackReceived = false;
		ecp_rx_run_sm(vd);
		break;
	case ECP_ACK:
		LLDPAD_DBG("%s-%s: received ACK frame\n",
			   __func__, vd->ifname);
		vd->ecp.ackReceived = true;
		vdp_ack_profiles(vd, vd->ecp.seqECPDU);
		ecp_tx_run_sm(vd);
		vd->ecp.ackReceived = false;
		break;
	default:
		LLDPAD_ERR("ERROR: unknown mode %i\n", ecp_hdr->mode);
		return;
	}

	ecp_rx_freeFramein(vd);
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

	LLDPAD_DBG("%s-%s: validating frame\n", __func__, vd->ifname);

	assert(vd->ecp.rx.framein && vd->ecp.rx.sizein);

	tlv_offset = sizeof(struct l2_ethhdr);

	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.framein[tlv_offset];

	LLDPAD_DBG("%s-%s: ecp packet with subtype %#x mode %#x seq %#04x\n",
		   __func__, vd->ifname, ecp_hdr->subtype, ecp_hdr->mode,
		   ntohs(ecp_hdr->seqnr));

	if (ecp_hdr->subtype != ECP_SUBTYPE) {
		LLDPAD_ERR("ERROR: unknown subtype\n");
		return;
	}

	if ((ecp_hdr->oui[0] != 0x0) || (ecp_hdr->oui[1] != 0x1b) ||
		(ecp_hdr->oui[2] != 0x3f)) {
		LLDPAD_ERR("ERROR: incorrect OUI 0x%02x%02x%02x\n",
			   ecp_hdr->oui[0], ecp_hdr->oui[1], ecp_hdr->oui[2]);
		return;
	}

	switch(ecp_hdr->mode) {
	case ECP_REQUEST:
		break;
	case ECP_ACK:
		break;
	default:
		LLDPAD_ERR("ERROR: unknown mode %i\n", ecp_hdr->mode);
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

	LLDPAD_DBG("%s-%s: processing frame\n", __func__, vd->ifname);

	assert(vd->ecp.rx.framein && vd->ecp.rx.sizein);

	tlv_offset = sizeof(struct l2_ethhdr);

	ecp_hdr = (struct ecp_hdr *)&vd->ecp.rx.framein[tlv_offset];

	LLDPAD_DBG("%s-%s: ecp packet with subtype %#x mode %#x seq %#04x\n",
		   __func__, vd->ifname, ecp_hdr->subtype,
		   ecp_hdr->mode, ntohs(ecp_hdr->seqnr));

	if (ecp_hdr->mode == ECP_ACK)
		return;

	/* processing of VSI_TLVs starts here */

	tlv_offset += sizeof(struct ecp_hdr);

	vdp_called = 0;
	do {
		tlv_cnt++;

		if (tlv_offset > vd->ecp.rx.sizein) {
			LLDPAD_ERR("%s-%s: ERROR: Frame overrun! tlv_offset %i sizein %i cnt %i\n",
				   __func__, vd->ifname, tlv_offset,
				   vd->ecp.rx.sizein, tlv_cnt);
			frame_error++;
			goto out;
		}

		if (tlv_offset + 2 > vd->ecp.rx.sizein) {
			LLDPAD_DBG("%s: tlv EOF problem size=%d offset=%d\n",
				   __func__, vd->ecp.rx.sizein, tlv_offset);
			frame_error++;
			goto out;
		}

		tlv_head_ptr = (u16 *)&vd->ecp.rx.framein[tlv_offset];
		tlv_length = htons(*tlv_head_ptr) & 0x01FF;
		tlv_type = (u8)(htons(*tlv_head_ptr) >> 9);

		u16 tmp_offset = tlv_offset + tlv_length;
		if (tmp_offset > vd->ecp.rx.sizein) {
			LLDPAD_ERR("ERROR: Frame overflow error: offset=%d, "
				   "rx.size=%d\n",
				   tmp_offset, vd->ecp.rx.sizein);
			frame_error++;
			goto out;
		}

		u8 *info = (u8 *)&vd->ecp.rx.framein[tlv_offset +
					sizeof(*tlv_head_ptr)];

		struct unpacked_tlv *tlv = create_tlv();

		if (!tlv) {
			LLDPAD_ERR("ERROR: Failed malloc for incoming TLV\n");
			goto out;
		}

		if ((tlv_length == 0) && (tlv->type != TYPE_0)) {
				LLDPAD_ERR("ERROR: tlv_length == 0\n");
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
			LLDPAD_ERR("ERROR: Failed malloc for incoming TLV info\n");
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
			LLDPAD_DBG("%s: TLV (%u) was not stored (%p)\n",
				   __func__, tlv->type, tlv);
			tlv = free_unpkd_tlv(tlv);
			vd->ecp.stats.statsTLVsUnrecognizedTotal++;
		}

		tlv = NULL;
		tlv_stored = false;

	} while (tlv_offset < vd->ecp.rx.sizein);

out:
	if (frame_error) {
		vd->ecp.stats.statsFramesDiscardedTotal++;
		vd->ecp.stats.statsFramesInErrorsTotal++;
		vd->ecp.rx.badFrame = true;
	}
	if (vdp_called)
		vdp_advance_sm(vd);
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
void ecp_rx_change_state(struct vdp_data *vd, u8 newstate)
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
		LLDPAD_ERR("%s: LLDP RX state machine invalid state %d\n",
			   vd->ifname, newstate);
	}

	LLDPAD_DBG("%s-%s: state change %s -> %s\n", __func__,
		   vd->ifname, ecp_rx_states[vd->ecp.rx.state],
		   ecp_rx_states[newstate]);

	vd->ecp.rx.state = newstate;
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

	if (port->portEnabled == false) {
		ecp_rx_change_state(vd, ECP_RX_IDLE);
	}

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
			LLDPAD_DBG("%s:-(%s) seqECPDU %x, lastSequence %x\n",
				   __func__, vd->ifname, vd->ecp.seqECPDU,
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
		LLDPAD_ERR("%s: LLDP RX state machine in invalid state %d\n",
			   vd->ifname, vd->ecp.rx.state);
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
void ecp_rx_run_sm(struct vdp_data *vd)
{
	ecp_set_rx_state(vd);
	do {
		LLDPAD_DBG("%s-%s: ecp_rx - %s\n", __func__,
		       vd->ifname, ecp_rx_states[vd->ecp.tx.state]);

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
				ecp_rx_freeFramein(vd);
			}
			break;
		default:
			LLDPAD_ERR("%s: LLDP RX state machine in invalid state %d\n",
				   vd->ifname, vd->ecp.rx.state);
		}
	} while (ecp_set_rx_state(vd) == true);
}
