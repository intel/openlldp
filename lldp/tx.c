/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

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

bool mibConstrInfoLLDPDU(struct port *port, struct lldp_agent *agent)
{
	struct l2_ethhdr eth;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	u32 datasize = 0;
	struct packed_tlv *ptlv =  NULL;
	struct lldp_module *np;
	char macstring[30];

	if (agent->tx.frameout) {
		free(agent->tx.frameout);
		agent->tx.frameout = NULL;
	}

	mac2str(agent->mac_addr, macstring, 30);
	LLDPAD_DBG("%s: port %s mac %s type %i.\n", __func__, port->ifname,
		   macstring, agent->type);

	memcpy(eth.h_dest, agent->mac_addr, ETH_ALEN);
	l2_packet_get_own_src_addr(port->l2,(u8 *)&own_addr);
	memcpy(eth.h_source, &own_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_LLDP);
	agent->tx.frameout =  (u8 *)malloc(ETH_FRAME_LEN);
	if (agent->tx.frameout == NULL) {
		LLDPAD_DBG("InfoLLDPDU: Failed to malloc frame buffer \n");
		return false;
	}

	memset(agent->tx.frameout, 0, ETH_FRAME_LEN);
	memcpy(agent->tx.frameout, (void *)&eth, sizeof(struct l2_ethhdr));
	fb_offset += sizeof(struct l2_ethhdr);

	/* Generic TLV Pack */
	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops || !np->ops->lldp_mod_gettlv)
			continue;

		ptlv = np->ops->lldp_mod_gettlv(port, agent);
		if (ptlv) {
			if ((ptlv->size+fb_offset) > ETH_DATA_LEN)
				goto error;
			memcpy(agent->tx.frameout+fb_offset,
			       ptlv->tlv, ptlv->size);
			datasize += ptlv->size;
			fb_offset += ptlv->size;
			ptlv =  free_pkd_tlv(ptlv);
		}
	}

	/* The End TLV marks the end of the LLDP PDU */
	ptlv = pack_end_tlv();
	if (!ptlv || ((ptlv->size + fb_offset) > ETH_DATA_LEN))
		goto error;
	memcpy(agent->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
	datasize += ptlv->size;
	fb_offset += ptlv->size;
	ptlv =  free_pkd_tlv(ptlv);

	if (datasize < ETH_MIN_DATA_LEN)
		agent->tx.sizeout = ETH_ZLEN;
	else
		agent->tx.sizeout = fb_offset;

	return true;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (agent->tx.frameout)
		free(agent->tx.frameout);
	agent->tx.frameout = NULL;
	LLDPAD_DBG("InfoLLDPDU: packed TLV too large for tx frame\n");
	return false;
}

void txInitializeLLDP(struct lldp_agent *agent)
{
	if (agent->tx.frameout) {
		free(agent->tx.frameout);
		agent->tx.frameout = NULL;
	}

	agent->tx.state  = TX_LLDP_INITIALIZE;
	agent->tx.localChange = false;
	agent->stats.statsFramesOutTotal = 0;
	agent->timers.reinitDelay   = REINIT_DELAY;
	agent->timers.msgTxHold     = DEFAULT_TX_HOLD;
	agent->timers.msgTxInterval = DEFAULT_TX_INTERVAL;
	agent->timers.msgFastTx     = FAST_TX_INTERVAL;

	agent->tx.txTTL = 0;
	agent->msap.length1 = 0;
	agent->msap.msap1 = NULL;
	agent->msap.length2 = 0;
	agent->msap.msap2 = NULL;
	agent->lldpdu = false;

	return;
}

void txInitializeTimers(struct lldp_agent *agent)
{
	agent->timers.txTick = false;
	agent->tx.txNow = false;
	agent->tx.localChange = false;
	agent->timers.txTTR = 0;
	agent->tx.txFast = 0;
	agent->timers.txShutdownWhile = 0;
	agent->rx.newNeighbor = false;
	agent->timers.txMaxCredit = TX_CREDIT_MAX;
	agent->timers.txCredit = TX_CREDIT_MAX;
	agent->timers.txFastInit = TX_FAST_INIT;
	agent->timers.state = TX_TIMER_BEGIN;
	return;
}

bool mibConstrShutdownLLDPDU(struct port *port, struct lldp_agent *agent)
{
	struct l2_ethhdr eth;
	u8  own_addr[ETH_ALEN];
	u32 fb_offset = 0;
	u32 datasize = 0;
	struct packed_tlv *ptlv =  NULL;
	struct lldp_module *np;
	char macstring[30];

	if (agent->tx.frameout) {
		free(agent->tx.frameout);
		agent->tx.frameout = NULL;
	}

	mac2str(agent->mac_addr, macstring, 30);
	LLDPAD_DBG("%s: mac %s.\n", __func__, macstring);

	memcpy(eth.h_dest, agent->mac_addr, ETH_ALEN);
	l2_packet_get_own_src_addr(port->l2,(u8 *)&own_addr);
	memcpy(eth.h_source, &own_addr, ETH_ALEN);
	eth.h_proto = htons(ETH_P_LLDP);
	agent->tx.frameout =  (u8 *)malloc(ETH_FRAME_LEN);
	if (agent->tx.frameout == NULL) {
		LLDPAD_DBG("ShutdownLLDPDU: Failed to malloc frame buffer \n");
		return false;
	}
	memset(agent->tx.frameout,0,ETH_FRAME_LEN);
	memcpy(agent->tx.frameout, (void *)&eth, sizeof(struct l2_ethhdr));
	fb_offset += sizeof(struct l2_ethhdr);

	np = find_module_by_id(&lldp_head, LLDP_MOD_MAND);
	if (!np)
		goto error;
	if (!np->ops || !np->ops->lldp_mod_gettlv)
		goto error;
	ptlv = np->ops->lldp_mod_gettlv(port, agent);
	if (ptlv) {
		if ((ptlv->size + fb_offset) > ETH_DATA_LEN)
			goto error;
		/* set the TTL to be 0 TTL TLV */
		memset(&ptlv->tlv[ptlv->size - 2], 0, 2);
		memcpy(agent->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
		datasize += ptlv->size;
		fb_offset += ptlv->size;
		ptlv =  free_pkd_tlv(ptlv);
	}

	/* The End TLV marks the end of the LLDP PDU */
	ptlv = pack_end_tlv();
	if (!ptlv || ((ptlv->size + fb_offset) > ETH_DATA_LEN))
		goto error;
	memcpy(agent->tx.frameout + fb_offset, ptlv->tlv, ptlv->size);
	datasize += ptlv->size;
	fb_offset += ptlv->size;
	ptlv = free_pkd_tlv(ptlv);

	if (datasize < ETH_MIN_DATA_LEN)
		agent->tx.sizeout = ETH_ZLEN;
	else
		agent->tx.sizeout = fb_offset;
	return true;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (agent->tx.frameout)
		free(agent->tx.frameout);
	agent->tx.frameout = NULL;
	LLDPAD_DBG("InfoLLDPDU: packed TLV too large for tx frame\n");
	return false;
}

u8 txFrame(struct port *port, struct lldp_agent *agent)
{
	l2_packet_send(port->l2, agent->mac_addr,
		htons(ETH_P_LLDP), agent->tx.frameout, agent->tx.sizeout);

	agent->stats.statsFramesOutTotal++;

	return 0;
}


void run_tx_sm(struct port *port, struct lldp_agent *agent)
{
	set_tx_state(port, agent);
	do {
		switch(agent->tx.state) {
		case TX_LLDP_INITIALIZE:
			txInitializeLLDP(agent);
			break;
		case TX_IDLE:
			process_tx_idle(agent);
			break;
		case TX_SHUTDOWN_FRAME:
			process_tx_shutdown_frame(port, agent);
			break;
		case TX_INFO_FRAME:
			process_tx_info_frame(port, agent);
			break;
		default:
			LLDPAD_DBG("ERROR The TX State Machine is broken!\n");
		}
	} while (set_tx_state(port, agent) == true);

	return;
}

bool set_tx_state(struct port *port, struct lldp_agent *agent)
{
	if ((port->portEnabled == false) && (port->prevPortEnabled == true)) {
		LLDPAD_DBG("set_tx_state: port was disabled\n");
		tx_change_state(port, agent, TX_LLDP_INITIALIZE);
	}
	port->prevPortEnabled = port->portEnabled;

	switch (agent->tx.state) {
	case TX_LLDP_INITIALIZE:
		if (port->portEnabled && ((agent->adminStatus == enabledRxTx) ||
			(agent->adminStatus == enabledTxOnly))) {
			tx_change_state(port, agent, TX_IDLE);
			return true;
		}
		return false;
	case TX_IDLE:
		if ((agent->adminStatus == disabled) ||
			(agent->adminStatus == enabledRxOnly)) {
			tx_change_state(port, agent, TX_SHUTDOWN_FRAME);
			return true;
		}
		if ((agent->tx.txNow) && ((agent->timers.txCredit > 0))) {
			tx_change_state(port, agent, TX_INFO_FRAME);
			return true;
		}
		return false;
	case TX_SHUTDOWN_FRAME:
		if (agent->timers.txShutdownWhile == 0) {
			tx_change_state(port, agent, TX_LLDP_INITIALIZE);
			return true;
		}
		return false;
	case TX_INFO_FRAME:
		tx_change_state(port, agent, TX_IDLE);
		return true;
	default:
		LLDPAD_DBG("ERROR: The TX State Machine is broken!\n");
		return false;
	}
}

void process_tx_idle(UNUSED struct lldp_agent *agent)
{
	return;
}

void process_tx_shutdown_frame(struct port *port, struct lldp_agent *agent)
{
	if (agent->timers.txShutdownWhile == 0) {
		if (mibConstrShutdownLLDPDU(port, agent))
			txFrame(port, agent);
		agent->timers.txShutdownWhile = agent->timers.reinitDelay;
	}
	return;
}

void process_tx_info_frame(struct port *port, struct lldp_agent *agent)
{
	mibConstrInfoLLDPDU(port, agent);

	txFrame(port, agent);
	if (agent->timers.txCredit > 0)
		agent->timers.txCredit--;
	agent->tx.txNow = false;
	return;
}

void update_tx_timers(struct lldp_agent *agent)
{
	if (agent->timers.txTTR)
		agent->timers.txTTR--;

	agent->timers.txTick = true;
	return;
}

void	tx_timer_change_state(struct lldp_agent *agent, u8 newstate)
{
	switch(newstate) {
	case TX_TIMER_INITIALIZE:
		break;
	case TX_TIMER_IDLE:
		break;
	case TX_TIMER_EXPIRES:
		break;
	case TX_TICK:
		break;
	case SIGNAL_TX:
		break;
	case TX_FAST_START:
		break;
	default:
		LLDPAD_DBG("ERROR: tx_timer_change_state:  default\n");
	}

	agent->timers.state = newstate;
	return;
}

bool	set_tx_timers_state(struct port *port, struct lldp_agent *agent)
{
	if ((agent->timers.state == TX_TIMER_BEGIN) ||
	    (port->portEnabled == false) || (agent->adminStatus == disabled) ||
	    (agent->adminStatus == enabledRxOnly)) {
		tx_timer_change_state(agent, TX_TIMER_INITIALIZE);
	}

	switch (agent->timers.state) {
	case TX_TIMER_INITIALIZE:
		if (port->portEnabled && ((agent->adminStatus == enabledRxTx) ||
			(agent->adminStatus == enabledTxOnly))) {
			tx_timer_change_state(agent, TX_TIMER_IDLE);
			return true;
		}
		return false;
	case TX_TIMER_IDLE:
		if (agent->tx.localChange) {
			tx_timer_change_state(agent, SIGNAL_TX);
			return true;
		}

		if (agent->timers.txTTR == 0) {
			tx_timer_change_state(agent, TX_TIMER_EXPIRES);
			return true;
		}

		if (agent->rx.newNeighbor) {
			tx_timer_change_state(agent, TX_FAST_START);
			return true;
		}

		if (agent->timers.txTick) {
			tx_timer_change_state(agent, TX_TICK);
			return true;
		}
		return false;
	case TX_TIMER_EXPIRES:
		tx_timer_change_state(agent, SIGNAL_TX);
		return true;
	case SIGNAL_TX:
	case TX_TICK:
		tx_timer_change_state(agent, TX_TIMER_IDLE);
		return true;
	case TX_FAST_START:
		tx_timer_change_state(agent, TX_TIMER_EXPIRES);
		return true;
	default:
		LLDPAD_DBG("ERROR: The TX State Machine is broken!\n");
		return false;
	}
}

void	run_tx_timers_sm(struct port *port, struct lldp_agent *agent)
{
	set_tx_timers_state(port, agent);
	do {
		switch(agent->timers.state) {
		case TX_TIMER_INITIALIZE:
			txInitializeTimers(agent);
			break;
		case TX_TIMER_IDLE:
			break;
		case TX_TIMER_EXPIRES:
			if (agent->tx.txFast)
				agent->tx.txFast--;
			break;
		case TX_TICK:
			agent->timers.txTick = false;
			if (agent->timers.txCredit < agent->timers.txMaxCredit)
				agent->timers.txCredit++;
			break;
		case SIGNAL_TX:
			agent->tx.txNow = true;
			agent->tx.localChange = false;
			if (agent->tx.txFast)
				agent->timers.txTTR = agent->timers.msgFastTx;
			else
				agent->timers.txTTR = agent->timers.msgTxInterval;
			break;
		case TX_FAST_START:
			agent->rx.newNeighbor = false;
			if (agent->tx.txFast == 0)
				agent->tx.txFast = agent->timers.txFastInit;
			break;
		default:
			LLDPAD_DBG("ERROR The TX Timer State Machine "
				   "is broken!\n");
		}
	} while (set_tx_timers_state(port, agent) == true);

	return;
}

void tx_change_state(struct port *port, struct lldp_agent *agent, u8 newstate)
{
	switch(newstate) {
	case TX_LLDP_INITIALIZE:
		if ((agent->tx.state != TX_SHUTDOWN_FRAME) &&
			port->portEnabled) {
			assert(port->portEnabled);
		}
		break;
	case TX_IDLE:
		if (!(agent->tx.state == TX_LLDP_INITIALIZE ||
			agent->tx.state == TX_INFO_FRAME)) {
			assert(agent->tx.state == TX_LLDP_INITIALIZE);
			assert(agent->tx.state == TX_INFO_FRAME);
		}
		break;
	case TX_SHUTDOWN_FRAME:
	case TX_INFO_FRAME:
		assert(agent->tx.state == TX_IDLE);
		break;
	default:
		LLDPAD_DBG("ERROR: tx_change_state:  default\n");
	}

	agent->tx.state = newstate;
	return;
}
