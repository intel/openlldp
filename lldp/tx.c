/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2010 Intel Corporation.

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

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#include <stdlib.h>
#include <assert.h>
#include "ports.h"
#include "l2_packet.h"
#include "states.h"
#include "messages.h"
#include "lldpad.h"
#include "lldp_tlv.h"
#include "lldp_mod.h"
#include "lldp_mand.h"

bool mibConstrInfoLLDPDU(struct port *port)
{
	struct l2_ethhdr eth;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	u32 datasize = 0;
	struct packed_tlv *ptlv =  NULL;
	struct lldp_module *np;

	if (port->tx.frameout) {
		free(port->tx.frameout);
		port->tx.frameout = NULL;
	}

	memcpy(eth.h_dest, multi_cast_source, ETH_ALEN);
	l2_packet_get_own_src_addr(port->l2,(u8 *)&own_addr);
	memcpy(eth.h_source, &own_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_LLDP);
	port->tx.frameout =  (u8 *)malloc(ETH_FRAME_LEN);
	if (port->tx.frameout == NULL) {
		LLDPAD_DBG("InfoLLDPDU: Failed to malloc frame buffer \n");
		return false;
	}
	memset(port->tx.frameout,0,ETH_FRAME_LEN);
	memcpy(port->tx.frameout, (void *)&eth, sizeof(struct l2_ethhdr));
	fb_offset += sizeof(struct l2_ethhdr);

	/* Generic TLV Pack */
	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops || !np->ops->lldp_mod_gettlv)
			continue;

		ptlv = np->ops->lldp_mod_gettlv(port);
		if (ptlv) {
			if ((ptlv->size+fb_offset) > ETH_MAX_DATA_LEN)
				goto error;
			memcpy(port->tx.frameout+fb_offset,
			       ptlv->tlv, ptlv->size);
			datasize += ptlv->size;
			fb_offset += ptlv->size;
			ptlv =  free_pkd_tlv(ptlv);
		}
	}

	/* The End TLV marks the end of the LLDP PDU */
	ptlv = pack_end_tlv();
	if (!ptlv || ((ptlv->size + fb_offset) > ETH_MAX_DATA_LEN))
		goto error;
	memcpy(port->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
	datasize += ptlv->size;
	fb_offset += ptlv->size;
	ptlv =  free_pkd_tlv(ptlv);

	if (datasize < ETH_MIN_DATA_LEN)
		port->tx.sizeout = ETH_MIN_PKT_LEN;
	else
		port->tx.sizeout = fb_offset;

	return true;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (port->tx.frameout)
		free(port->tx.frameout);
	port->tx.frameout = NULL;
	LLDPAD_DBG("InfoLLDPDU: packed TLV too large for tx frame\n");
	return false;
}

void txInitializeLLDP(struct port *port)
{
	if (port->tx.frameout) {
		free(port->tx.frameout);
		port->tx.frameout = NULL;
	}
	port->tx.localChange = 1;
	port->stats.statsFramesOutTotal = 0;
	port->timers.reinitDelay   = REINIT_DELAY;
	port->timers.msgTxHold     = DEFAULT_TX_HOLD;
	port->timers.msgTxInterval = FASTSTART_TX_INTERVAL;
	port->timers.txDelay       = FASTSTART_TX_DELAY;
	port->timers.txShutdownWhile = 0;
	port->timers.txDelayWhile = 0;
	return;
}

bool mibConstrShutdownLLDPDU(struct port *port)
{
	struct l2_ethhdr eth;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	u32 datasize = 0;
	struct packed_tlv *ptlv =  NULL;
	struct lldp_module *np;

	if (port->tx.frameout) {
		free(port->tx.frameout);
		port->tx.frameout = NULL;
	}

	memcpy(eth.h_dest, multi_cast_source, ETH_ALEN);
	l2_packet_get_own_src_addr(port->l2,(u8 *)&own_addr);
	memcpy(eth.h_source, &own_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_LLDP);
	port->tx.frameout =  (u8 *)malloc(ETH_FRAME_LEN);
	if (port->tx.frameout == NULL) {
		LLDPAD_DBG("ShutdownLLDPDU: Failed to malloc frame buffer \n");
		return false;
	}
	memset(port->tx.frameout,0,ETH_FRAME_LEN);
	memcpy(port->tx.frameout, (void *)&eth, sizeof(struct l2_ethhdr));
	fb_offset += sizeof(struct l2_ethhdr);

	np = find_module_by_id(&lldp_head, LLDP_MOD_MAND);
	if (!np)
		goto error;
	if (!np->ops || !np->ops->lldp_mod_gettlv)
		goto error;
	ptlv = np->ops->lldp_mod_gettlv(port);
	if (ptlv) {
		if ((ptlv->size + fb_offset) > ETH_MAX_DATA_LEN)
			goto error;
		/* set the TTL to be 0 TTL TLV */
		memset(&ptlv->tlv[ptlv->size - 2], 0, 2);
		memcpy(port->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
		datasize += ptlv->size;
		fb_offset += ptlv->size;
		ptlv =  free_pkd_tlv(ptlv);
	}

	/* The End TLV marks the end of the LLDP PDU */
	ptlv = pack_end_tlv();
	if (!ptlv || ((ptlv->size + fb_offset) > ETH_MAX_DATA_LEN))
		goto error;
	memcpy(port->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
	datasize += ptlv->size;
	fb_offset += ptlv->size;
	ptlv = free_pkd_tlv(ptlv);

	if (datasize < ETH_MIN_DATA_LEN)
		port->tx.sizeout = ETH_MIN_PKT_LEN;
	else
		port->tx.sizeout = fb_offset;
	return true;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (port->tx.frameout)
		free(port->tx.frameout);
	port->tx.frameout = NULL;
	LLDPAD_DBG("InfoLLDPDU: packed TLV too large for tx frame\n");
	return false;
}

u8 txFrame(struct port *port)
{

	int status = 0;

	status = l2_packet_send(port->l2, (u8 *)&multi_cast_source,
		htons(ETH_P_LLDP),port->tx.frameout,port->tx.sizeout);
	port->stats.statsFramesOutTotal++;
	if (port->stats.statsFramesOutTotal == FASTSTART_TX_COUNT) {
		/* We sent the fast start transmissions */
		port->timers.msgTxInterval = DEFAULT_TX_INTERVAL;
		port->timers.txDelay       = DEFAULT_TX_DELAY;
	}

	return 0;
}


void run_tx_sm(struct port *port, bool update_timers)
{
	if (update_timers)
		update_tx_timers(port);

	set_tx_state(port);
	do {
		switch(port->tx.state) {
		case TX_LLDP_INITIALIZE:
			txInitializeLLDP(port);
			break;
		case TX_IDLE:
			process_tx_idle(port);
			break;
		case TX_SHUTDOWN_FRAME:
			process_tx_shutdown_frame(port);
			break;
		case TX_INFO_FRAME:
			process_tx_info_frame(port);
			break;
		default:
			LLDPAD_DBG("ERROR The TX State Machine is broken!\n");
		}
	} while (set_tx_state(port) == true);

	return;
}

bool set_tx_state(struct port *port)
{
	if ((port->portEnabled == false) && (port->prevPortEnabled == true)) {
		LLDPAD_DBG("set_tx_state: port was disabled\n");
		tx_change_state(port, TX_LLDP_INITIALIZE);
	}
	port->prevPortEnabled = port->portEnabled;

	switch (port->tx.state) {
	case TX_LLDP_INITIALIZE:
		if (port->portEnabled && ((port->adminStatus == enabledRxTx) ||
			(port->adminStatus == enabledTxOnly))) {
			tx_change_state(port, TX_IDLE);
			return true;
		}
		return false;
	case TX_IDLE:
		if ((port->adminStatus == disabled) ||
			(port->adminStatus == enabledRxOnly)) {
			tx_change_state(port, TX_SHUTDOWN_FRAME);
			return true;
		}
		if ((port->timers.txDelayWhile == 0) &&
			((port->timers.txTTR == 0) ||
			(port->tx.localChange))) {
			tx_change_state(port, TX_INFO_FRAME);
			return true;
		}
		return false;
	case TX_SHUTDOWN_FRAME:
		if (port->timers.txShutdownWhile == 0) {
			tx_change_state(port, TX_LLDP_INITIALIZE);
			return true;
		}
		return false;
	case TX_INFO_FRAME:
		tx_change_state(port, TX_IDLE);
		return true;
	default:
		LLDPAD_DBG("ERROR: The TX State Machine is broken!\n");
		return false;
	}
}

void process_tx_idle(struct port *port)
{
	return;
}

void process_tx_shutdown_frame(struct port *port)
{
	if (port->timers.txShutdownWhile == 0) {
		if (mibConstrShutdownLLDPDU(port))
			txFrame(port);
		port->timers.txShutdownWhile = port->timers.reinitDelay;
	}
	return;
}

void process_tx_info_frame(struct port *port)
{
	if (port->tx.localChange)
		mibConstrInfoLLDPDU(port);

	txFrame(port);
	port->tx.localChange = false;
	return;
}

void	update_tx_timers(struct port *port)
{
	if (port->timers.txShutdownWhile)
		port->timers.txShutdownWhile--;

	if (port->timers.txDelayWhile)
		port->timers.txDelayWhile--;

	if (port->timers.txTTR)
		port->timers.txTTR--;
	return;
}

void tx_change_state(struct port *port, u8 newstate)
{
	u32 tmpTTL = 0;

	switch(newstate) {
	case TX_LLDP_INITIALIZE:
		if ((port->tx.state != TX_SHUTDOWN_FRAME) &&
			port->portEnabled) {
			assert(port->portEnabled);
		}
		break;
	case TX_IDLE:
		if (!(port->tx.state == TX_LLDP_INITIALIZE ||
			port->tx.state == TX_INFO_FRAME)) {
			assert(port->tx.state == TX_LLDP_INITIALIZE);
			assert(port->tx.state == TX_INFO_FRAME);
		}
		tmpTTL = DEFAULT_TX_INTERVAL * port->timers.msgTxHold;

		if (tmpTTL > 65535)
			port->tx.txTTL = htons(65535);
		else
			port->tx.txTTL = htons((u16)tmpTTL);

		tmpTTL = 0;
		port->timers.txTTR = port->timers.msgTxInterval;
		port->timers.txDelayWhile = port->timers.txDelay;
		break;
	case TX_SHUTDOWN_FRAME:
	case TX_INFO_FRAME:
		assert(port->tx.state == TX_IDLE);
		break;
	default:
		LLDPAD_DBG("ERROR: tx_change_state:  default\n");
	}

	port->tx.state = newstate;
	return;
}
