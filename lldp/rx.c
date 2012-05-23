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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "ports.h"
#include "l2_packet.h"
#include "states.h"
#include "mibdata.h"
#include "messages.h"
#include "lldp.h"
#include "lldpad.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp_mand.h"
#include "lldp_tlv.h"
#include "agent.h"

void rxInitializeLLDP(struct port *port, struct lldp_agent *agent)
{
	agent->rx.rcvFrame = false;
	agent->rx.badFrame = false;
	agent->rx.tooManyNghbrs = false;
	agent->rx.rxInfoAge = false;
	if (agent->rx.framein) {
		free(agent->rx.framein);
		agent->rx.framein = NULL;
	}
	agent->rx.sizein = 0;

	mibDeleteObjects(port, agent);
	return;
}

void rxReceiveFrame(void *ctx, UNUSED int ifindex, const u8 *buf, size_t len)
{
	struct port * port;
	struct lldp_agent *agent;
	u8  frame_error = 0;
	struct l2_ethhdr *hdr;
	struct l2_ethhdr example_hdr,*ex;

	/* Drop and ignore zero length frames */
	if (!len)
		return;

	port = (struct port *)ctx;

	/* walk through the list of agents for this interface and see if we
	 * can find a matching agent */
	LIST_FOREACH(agent, &port->agent_head, entry) {
		if (agent->rx.framein &&
		    agent->rx.sizein == len &&
		    (memcmp(buf, agent->rx.framein, len) == 0)) {
			agent->timers.rxTTL = agent->timers.lastrxTTL;
			agent->stats.statsFramesInTotal++;
			return;
		}

		ex = &example_hdr;
		memcpy(ex->h_dest, agent->mac_addr, ETH_ALEN);
		ex->h_proto = htons(ETH_P_LLDP);
		hdr = (struct l2_ethhdr *)buf;

		if (hdr->h_proto != example_hdr.h_proto) {
			LLDPAD_INFO("ERROR Ethertype not LLDP ethertype but ethertype "
				"'%x' in incoming frame.\n", htons(hdr->h_proto));
			frame_error++;
			return;
		}

		if ((!memcmp(hdr->h_dest,ex->h_dest, ETH_ALEN)))
			break;
	}

	if (agent == NULL)
		return;

	if (agent->adminStatus == disabled || agent->adminStatus == enabledTxOnly)
		return;

	if (agent->rx.framein)
		free(agent->rx.framein);

	agent->rx.sizein = (u16)len;
	agent->rx.framein = (u8 *)malloc(len);

	if (agent->rx.framein == NULL) {
		LLDPAD_DBG("ERROR - could not allocate memory for rx'ed frame\n");
		return;
	}
	memcpy(agent->rx.framein, buf, len);

	if (!frame_error) {
		agent->stats.statsFramesInTotal++;
		agent->rx.rcvFrame = 1;
	}

	run_rx_sm(port, agent);
}

void rxProcessFrame(struct port *port, struct lldp_agent *agent)
{
	u16 tlv_cnt = 0;
	u8  tlv_type = 0;
	u16 tlv_length = 0;
	u16 tlv_offset = 0;
	u16 *tlv_head_ptr = NULL;
	u8  frame_error = 0;
	bool msap_compare_1 = false;
	bool msap_compare_2 = false;
	bool good_neighbor  = false;
	bool tlv_stored     = false;
	int err;
	struct lldp_module *np;

	assert(agent->rx.framein && agent->rx.sizein);
	agent->lldpdu = 0;
	agent->rx.dupTlvs = 0;

	agent->rx.dcbx_st = 0;
	agent->rx.manifest = (rxmanifest *)malloc(sizeof(rxmanifest));
	if (agent->rx.manifest == NULL) {
		LLDPAD_DBG("ERROR - could not allocate memory for receive "
			"manifest\n");
		return;
	}
	memset(agent->rx.manifest, 0, sizeof(rxmanifest));
	get_remote_peer_mac_addr(port, agent);
	tlv_offset = sizeof(struct l2_ethhdr);  /* Points to 1st TLV */

	do {
		tlv_cnt++;
		if (tlv_offset > agent->rx.sizein) {
			LLDPAD_INFO("ERROR: Frame overrun!\n");
			frame_error++;
			goto out;
		}

		tlv_head_ptr = (u16 *)&agent->rx.framein[tlv_offset];
		tlv_length = htons(*tlv_head_ptr) & 0x01FF;
		tlv_type = (u8)(htons(*tlv_head_ptr) >> 9);

		if (tlv_cnt <= 3) {
			if (tlv_cnt != tlv_type) {
				LLDPAD_INFO("ERROR:TLV missing or TLVs out "
					"of order!\n");
				frame_error++;
				goto out;
			}
		}

		if (tlv_cnt > 3) {
			if ((tlv_type == 1) || (tlv_type == 2) ||
				(tlv_type == 3)) {
				LLDPAD_INFO("ERROR: Extra Type 1 Type2, or "
					"Type 3 TLV!\n");
				frame_error++;
				goto out;
			}
		}

		if ((tlv_type == TIME_TO_LIVE_TLV) && (tlv_length != 2)) {
			LLDPAD_INFO("ERROR:TTL TLV validation error! \n");
			frame_error++;
			goto out;
		}

		u16 tmp_offset = tlv_offset + tlv_length;
		if (tmp_offset > agent->rx.sizein) {
			LLDPAD_INFO("ERROR: Frame overflow error: offset=%d, "
				"rx.size=%d \n", tmp_offset, agent->rx.sizein);
			frame_error++;
			goto out;
		}

		u8 *info = (u8 *)&agent->rx.framein[tlv_offset +
					sizeof(*tlv_head_ptr)];

		struct unpacked_tlv *tlv = create_tlv();

		if (!tlv) {
			LLDPAD_DBG("ERROR: Failed to malloc space for "
				"incoming TLV. \n");
			goto out;
		}

		if ((tlv_length == 0) && (tlv->type != TYPE_0)) {
				LLDPAD_INFO("ERROR: tlv_length == 0\n");
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
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"TLV info \n");
			free_unpkd_tlv(tlv);
			goto out;
		}

		/* Validate the TLV */
		tlv_offset += sizeof(*tlv_head_ptr) + tlv_length;
		/* Get MSAP info */
		if (tlv->type == TYPE_1) { /* chassis ID */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE1) {
				LLDPAD_INFO("Received multiple Chassis ID"
					    "TLVs in this LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE1;
				agent->rx.manifest->chassis = tlv;
				tlv_stored = true;
			}

			if (agent->msap.msap1 == NULL) {
				agent->msap.length1 = tlv->length;
				agent->msap.msap1 = (u8 *)malloc(tlv->length);
				if (!(agent->msap.msap1)) {
					LLDPAD_DBG("ERROR: Failed to malloc "
						"space for msap1\n");
					free_unpkd_tlv(tlv);
					goto out;
				}
				memcpy(agent->msap.msap1, tlv->info,
					tlv->length);
			} else {
				if (tlv->length == agent->msap.length1) {
					if ((memcmp(tlv->info,agent->msap.msap1,
						tlv->length) == 0))
						msap_compare_1 = true;
				}
			}
		}
		if (tlv->type == TYPE_2) { /* port ID */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE2) {
				LLDPAD_INFO("Received multiple Port ID "
					"TLVs in this LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE2;
				agent->rx.manifest->portid = tlv;
				tlv_stored = true;
			}

			if (agent->msap.msap2 == NULL) {
				agent->msap.length2 = tlv->length;
				agent->msap.msap2 = (u8 *)malloc(tlv->length);
				if (!(agent->msap.msap2)) {
					LLDPAD_DBG("ERROR: Failed to malloc "
						"space for msap2\n");
					free_unpkd_tlv(tlv);
					goto out;
				}
				memcpy(agent->msap.msap2, tlv->info, tlv->length);
				agent->rx.newNeighbor = true;
			} else {
				if (tlv->length == agent->msap.length2) {
					if ((memcmp(tlv->info,agent->msap.msap2,
						tlv->length) == 0))
						msap_compare_2 = true;
				}
				if ((msap_compare_1 == true) &&
					(msap_compare_2 == true)) {
					msap_compare_1 = false;
					msap_compare_2 = false;
					good_neighbor = true;
				} else {
					/* New neighbor */
					agent->rx.tooManyNghbrs = true;
					agent->rx.newNeighbor = true;
					LLDPAD_INFO("** TOO_MANY_NGHBRS\n");
				}
			}
		}
		if (tlv->type == TYPE_3) { /* time to live */
			if (agent->lldpdu & RCVD_LLDP_TLV_TYPE3) {
				LLDPAD_INFO("Received multiple TTL TLVs in this"
					" LLDPDU\n");
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			} else {
				agent->lldpdu |= RCVD_LLDP_TLV_TYPE3;
				agent->rx.manifest->ttl = tlv;
				tlv_stored = true;
			}
			if ((agent->rx.tooManyNghbrs == true) &&
				(good_neighbor == false)) {
				LLDPAD_INFO("** set tooManyNghbrsTimer\n");
				agent->timers.tooManyNghbrsTimer =
					max(ntohs(*(u16 *)tlv->info),
					agent->timers.tooManyNghbrsTimer);
				msap_compare_1 = false;
				msap_compare_2 = false;
			} else {
				agent->timers.rxTTL = ntohs(*(u16 *)tlv->info);
				agent->timers.lastrxTTL = agent->timers.rxTTL;
				good_neighbor = false;
			}
		}
		if (tlv->type == TYPE_4) { /* port description */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE4;
			agent->rx.manifest->portdesc = tlv;
			tlv_stored = true;
		}
		if (tlv->type == TYPE_5) { /* system name */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE5;
			agent->rx.manifest->sysname = tlv;
			tlv_stored = true;
		}
		if (tlv->type == TYPE_6) { /* system description */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE6;
			agent->rx.manifest->sysdesc = tlv;
			tlv_stored = true;
		}
		if (tlv->type == TYPE_7) { /* system capabilities */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE7;
			agent->rx.manifest->syscap = tlv;
			tlv_stored = true;
		}
		if (tlv->type == TYPE_8) { /* mgmt address */
			agent->lldpdu |= RCVD_LLDP_TLV_TYPE8;
			agent->rx.manifest->mgmtadd = tlv;
			tlv_stored = true;
		}

		/* rx per lldp module */
		LIST_FOREACH(np, &lldp_head, lldp) {
			if (!np->ops || !np->ops->lldp_mod_rchange)
				continue;

			err = np->ops->lldp_mod_rchange(port, agent, tlv);

			if (!err)
				tlv_stored = true;
			else if (err == TLV_ERR) {
				frame_error++;
				free_unpkd_tlv(tlv);
				goto out;
			}
		}

		if (!tlv_stored) {
			LLDPAD_INFO("%s: allocated TLV %u was not stored! %p\n",
				   __func__, tlv->type, tlv);
			tlv = free_unpkd_tlv(tlv);
			agent->stats.statsTLVsUnrecognizedTotal++;
		}
		tlv = NULL;
		tlv_stored = false;
	} while(tlv_type != 0);

out:
	if (frame_error) {
		/* discard the frame because of errors. */
		agent->stats.statsFramesDiscardedTotal++;
		agent->stats.statsFramesInErrorsTotal++;
		agent->rx.badFrame = true;
	}

	agent->lldpdu = 0;
	clear_manifest(agent);

	return;
}

u8 mibDeleteObjects(struct port *port, struct lldp_agent *agent)
{
	struct lldp_module *np;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops || !np->ops->lldp_mod_mibdelete)
			continue;
		np->ops->lldp_mod_mibdelete(port, agent);
	}

	/* Clear history */
	agent->msap.length1 = 0;
	if (agent->msap.msap1) {
		free(agent->msap.msap1);
		agent->msap.msap1 = NULL;
	}

	agent->msap.length2 = 0;
	if (agent->msap.msap2) {
		free(agent->msap.msap2);
		agent->msap.msap2 = NULL;
	}
	return 0;
}

void run_rx_sm(struct port *port, struct lldp_agent *agent)
{
	set_rx_state(port, agent);
	do {
		switch(agent->rx.state) {
		case LLDP_WAIT_PORT_OPERATIONAL:
			break;
		case DELETE_AGED_INFO:
			process_delete_aged_info(port, agent);
			break;
		case RX_LLDP_INITIALIZE:
			process_rx_lldp_initialize(port, agent);
			break;
		case RX_WAIT_FOR_FRAME:
			process_wait_for_frame(agent);
			break;
		case RX_FRAME:
			process_rx_frame(port, agent);
			break;
		case DELETE_INFO:
			process_delete_info(port, agent);
			break;
		case UPDATE_INFO:
			process_update_info(agent);
			break;
		default:
			LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
		}
	} while (set_rx_state(port, agent) == true);
}

bool set_rx_state(struct port *port, struct lldp_agent *agent)
{
	if ((agent->rx.rxInfoAge == false) && (port->portEnabled == false)) {
		rx_change_state(agent, LLDP_WAIT_PORT_OPERATIONAL);
	}

	switch(agent->rx.state) {
	case LLDP_WAIT_PORT_OPERATIONAL:
		if (agent->rx.rxInfoAge == true) {
			rx_change_state(agent, DELETE_AGED_INFO);
			return true;
		} else if (port->portEnabled == true) {
			rx_change_state(agent, RX_LLDP_INITIALIZE);
			return true;
		}
		return false;
	case DELETE_AGED_INFO:
		rx_change_state(agent, LLDP_WAIT_PORT_OPERATIONAL);
		return true;
	case RX_LLDP_INITIALIZE:
		if ((agent->adminStatus == enabledRxTx) ||
			(agent->adminStatus == enabledRxOnly)) {
			rx_change_state(agent, RX_WAIT_FOR_FRAME);
			return true;
		}
		return false;
	case RX_WAIT_FOR_FRAME:
		if ((agent->adminStatus == disabled) ||
			(agent->adminStatus == enabledTxOnly)) {
			rx_change_state(agent, RX_LLDP_INITIALIZE);
			return true;
		}
		if (agent->rx.rxInfoAge == true) {
			rx_change_state(agent, DELETE_INFO);
			return true;
		} else if (agent->rx.rcvFrame == true) {
			rx_change_state(agent, RX_FRAME);
			return true;
		}
		return false;
	case DELETE_INFO:
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	case RX_FRAME:
		if (agent->timers.rxTTL == 0) {
			rx_change_state(agent, DELETE_INFO);
			return true;
		} else if ((agent->timers.rxTTL != 0) &&
			(agent->rxChanges == true)) {
			rx_change_state(agent, UPDATE_INFO);
			return true;
		}
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	case UPDATE_INFO:
		rx_change_state(agent, RX_WAIT_FOR_FRAME);
		return true;
	default:
		LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
		return false;
	}
}

void process_delete_aged_info(struct port *port, struct lldp_agent *agent)
{
	mibDeleteObjects(port, agent);
	agent->rx.rxInfoAge = false;
	agent->rx.remoteChange = true;
	return;
}

void process_rx_lldp_initialize(struct port *port, struct lldp_agent *agent)
{
	rxInitializeLLDP(port, agent);
	agent->rx.rcvFrame = false;
	return;
}

void process_wait_for_frame(struct lldp_agent *agent)
{
	agent->rx.badFrame  = false;
	agent->rx.rxInfoAge = false;
	return;
}

void process_rx_frame(struct port *port, struct lldp_agent *agent)
{
	agent->rx.remoteChange = false;
	agent->rxChanges = false;
	agent->rx.rcvFrame = false;
	rxProcessFrame(port, agent);
	return;
}

void process_delete_info(struct port *port, struct lldp_agent *agent)
{
	mibDeleteObjects(port, agent);

	if (agent->rx.framein) {
		free(agent->rx.framein);
		agent->rx.framein = NULL;
	}

	agent->rx.sizein = 0;
	agent->rx.remoteChange = true;
	return;
}

void process_update_info(struct lldp_agent *agent)
{
	agent->rx.remoteChange = true;
	return;
}

void update_rx_timers(struct lldp_agent *agent)
{

	if (agent->timers.rxTTL) {
		agent->timers.rxTTL--;
		if (agent->timers.rxTTL == 0) {
			agent->rx.rxInfoAge = true;
			if (agent->timers.tooManyNghbrsTimer != 0) {
				LLDPAD_DBG("** clear tooManyNghbrsTimer\n");
				agent->timers.tooManyNghbrsTimer = 0;
				agent->rx.tooManyNghbrs = false;
			}
		}
	}
	if (agent->timers.tooManyNghbrsTimer) {
		agent->timers.tooManyNghbrsTimer--;
		if (agent->timers.tooManyNghbrsTimer == 0) {
			LLDPAD_DBG("** tooManyNghbrsTimer timeout\n");
			agent->rx.tooManyNghbrs = false;
		}
	}
}

void rx_change_state(struct lldp_agent *agent, u8 newstate)
{
	switch(newstate) {
		case LLDP_WAIT_PORT_OPERATIONAL:
			break;
		case RX_LLDP_INITIALIZE:
			assert((agent->rx.state == LLDP_WAIT_PORT_OPERATIONAL) ||
			       (agent->rx.state == RX_WAIT_FOR_FRAME));
			break;
		case DELETE_AGED_INFO:
			assert(agent->rx.state ==
				LLDP_WAIT_PORT_OPERATIONAL);
			break;
		case RX_WAIT_FOR_FRAME:
			if (!(agent->rx.state == RX_LLDP_INITIALIZE ||
				agent->rx.state == DELETE_INFO ||
				agent->rx.state == UPDATE_INFO ||
				agent->rx.state == RX_FRAME)) {
				assert(agent->rx.state !=
					RX_LLDP_INITIALIZE);
				assert(agent->rx.state != DELETE_INFO);
				assert(agent->rx.state != UPDATE_INFO);
				assert(agent->rx.state != RX_FRAME);
			}
			break;
		case RX_FRAME:
			assert(agent->rx.state == RX_WAIT_FOR_FRAME);
			break;
		case DELETE_INFO:
			if (!(agent->rx.state == RX_WAIT_FOR_FRAME ||
				agent->rx.state == RX_FRAME)) {
				assert(agent->rx.state == RX_WAIT_FOR_FRAME);
				assert(agent->rx.state == RX_FRAME);
			}
			break;
		case UPDATE_INFO:
			assert(agent->rx.state == RX_FRAME);
			break;
		default:
			LLDPAD_DBG("ERROR: The RX State Machine is broken!\n");
	}
	agent->rx.state = newstate;
}

void clear_manifest(struct lldp_agent *agent)
{
	if (agent->rx.manifest->mgmtadd)
		agent->rx.manifest->mgmtadd =
			free_unpkd_tlv(agent->rx.manifest->mgmtadd);
	if (agent->rx.manifest->syscap)
		agent->rx.manifest->syscap =
			free_unpkd_tlv(agent->rx.manifest->syscap);
	if (agent->rx.manifest->sysdesc)
		agent->rx.manifest->sysdesc =
			free_unpkd_tlv(agent->rx.manifest->sysdesc);
	if (agent->rx.manifest->sysname)
		agent->rx.manifest->sysname =
			free_unpkd_tlv(agent->rx.manifest->sysname);
	if (agent->rx.manifest->portdesc)
		agent->rx.manifest->portdesc =
			free_unpkd_tlv(agent->rx.manifest->portdesc);
	if (agent->rx.manifest->ttl)
		agent->rx.manifest->ttl =
			free_unpkd_tlv(agent->rx.manifest->ttl);
	if (agent->rx.manifest->portid)
		agent->rx.manifest->portid =
			free_unpkd_tlv(agent->rx.manifest->portid);
	if (agent->rx.manifest->chassis)
		agent->rx.manifest->chassis =
			free_unpkd_tlv(agent->rx.manifest->chassis);
	free(agent->rx.manifest);
	agent->rx.manifest = NULL;
}
