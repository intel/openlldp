/******************************************************************************

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

******************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include "lldp.h"
#include "lldp_tlv.h"
#include "lldp_evb.h"
#include "lldp_evb_cmds.h"
#include "qbg_vdp.h"
#include "messages.h"
#include "config.h"

extern struct lldp_head lldp_head;

struct evb_data *evb_data(char *ifname, enum agent_type type)
{
	struct evb_user_data *ud;
	struct evb_data *ed = NULL;

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_EVB);
	if (ud) {
		LIST_FOREACH(ed, &ud->head, entry) {
			if (!strncmp(ifname, ed->ifname, IFNAMSIZ) &&
			    (type == ed->agenttype))
				return ed;
		}
	}
	return NULL;
}

static void evb_print_tlvinfo(char *ifname, struct tlv_info_evb *tlv)
{
	LLDPAD_INFO("%s evb supported/configured forwarding mode: %#02x/%#02x "
		    "capabilities: %#02x/%#02x vsis: %04i/%04i "
		    "rte: %02i\n", ifname,
		    tlv->smode, tlv->cmode, tlv->scap, tlv->ccap,
		    ntohs(tlv->svsi), ntohs(tlv->cvsi), tlv->rte);
}

static void evb_dump_tlv(char *ifname, struct unpacked_tlv *tlv)
{
	int i, left = 0;
	char buffer[256];

	for (i = 0; i < tlv->length; i++) {
		int c;

		c = snprintf(buffer + left,
			     sizeof buffer - left,
			     "%02x ", tlv->info[i]);

		if (c < 0 || (c >= (int)sizeof buffer - left))
			break;
		else
			left += c;
	}

	LLDPAD_DBG("%s:%s type %i length %i info %s\n",
		   __func__, ifname, tlv->type, tlv->length, buffer);
}

/*
 * Checks values received in TLV and takes over some values.
 * Sets the new suggestion in member tie to be send out to switch.
 */
static void evb_update_tlv(struct evb_data *ed)
{
	struct tlv_info_evb *recv = &ed->last;
	u8 valid = recv->smode &
		   (LLDP_EVB_CAPABILITY_FORWARD_STANDARD |
		    LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY);

	/*
	 * Waiting for valid packets to pour in if valid packet was received,
	 * - check parameters with what we have offered for this interface,
	 * - fill structure with data,
	 * - enable local tx
	 */
	if (!valid) {
		LLDPAD_ERR("Neither standard nor rr set as forwarding modes ");
		LLDPAD_ERR("for interface - %s\n", ed->ifname);

		return;
	}

	/*
	 * Check bridge capabilities against local policy
	 * if bridge supports RR and we support it as well, request it
	 * by setting smode in tlv to be sent out (ed->tie.smode)
	 */
	if ((recv->smode & ed->policy.smode) &
	    LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)
		ed->tie.cmode = LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	else
		ed->tie.cmode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;

	/* If both sides support RTE, support and configure it */
	if ((recv->scap & ed->policy.scap) & LLDP_EVB_CAPABILITY_PROTOCOL_RTE)
		ed->tie.ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_RTE;
	else
		ed->tie.ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_RTE;

	if ((ed->tie.scap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE) &&
	    (recv->rte > 0) && (ed->policy.rte > 0))
		ed->tie.rte = MAX(ed->policy.rte, recv->rte);

	/* If both sides support ECP, set it */
	if ((recv->scap & ed->policy.scap) & LLDP_EVB_CAPABILITY_PROTOCOL_ECP)
		ed->tie.ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_ECP;
	else
		ed->tie.ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_ECP;

	/* If both sides support VDP, set it. Also set number of VSIs */
	if ((recv->scap & ed->policy.scap) & LLDP_EVB_CAPABILITY_PROTOCOL_VDP) {
		ed->tie.ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
		ed->tie.cvsi = htons(vdp_vsis(ed->ifname));
		ed->tie.svsi = ed->policy.svsi;
	} else {
		ed->tie.ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
		ed->tie.cvsi = 0;
		ed->tie.svsi = 0;
	}
}

/*
 * Build the packed EVB TLV.
 * Returns a pointer to the packed tlv or 0 on failure.
 */
static struct packed_tlv *evb_build_tlv(struct evb_data *ed)
{
	struct packed_tlv *ptlv = 0;
	u8 infobuf[sizeof(struct tlv_info_evb)];
	struct unpacked_tlv tlv = {
		.type = ORG_SPECIFIC_TLV,
		.length = sizeof(struct tlv_info_evb),
		.info = infobuf
	};

	if (!ed->txmit)
		return ptlv;
	evb_update_tlv(ed);

	memcpy(tlv.info, &ed->tie, tlv.length);
	ptlv = pack_tlv(&tlv);
	if (ptlv) {
		LLDPAD_DBG("%s:%s TLV about to be sent out:\n", __func__,
			   ed->ifname);
		evb_dump_tlv(ed->ifname, &tlv);
	} else
		LLDPAD_DBG("%s:%s failed to pack EVB TLV\n", __func__,
			   ed->ifname);
	return ptlv;
}

/*
 * Function call to build and return module specific packed EVB TLV.
 * Returned packed_tlv is free'ed by caller of this function.
 */
static struct packed_tlv *evb_gettlv(struct port *port,
				     struct lldp_agent *agent)
{
	struct evb_data *ed;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb_data(port->ifname, agent->type);
	if (!ed) {
		LLDPAD_ERR("%s:%s agent %d failed\n", __func__, port->ifname,
			   agent->type);
		return 0;
	}
	return evb_build_tlv(ed);
}

/*
 * evb_rchange: process received EVB TLV LLDPDU
 *
 * TLV not consumed on error
 */
static int evb_rchange(struct port *port, struct lldp_agent *agent,
		       struct unpacked_tlv *tlv)
{
	struct evb_data *ed;
	u8 oui_subtype[OUI_SUB_SIZE] = LLDP_OUI_SUBTYPE;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb_data(port->ifname, agent->type);

	if (!ed)
		return SUBTYPE_INVALID;

	if (tlv->type == TYPE_127) {
		/* check for length */
		if (tlv->length < OUI_SUB_SIZE)
			return TLV_ERR;

		/* check for oui */
		if (memcmp(tlv->info, &oui_subtype, OUI_SUB_SIZE))
			return SUBTYPE_INVALID;

		/* disable rx if tx has been disabled by administrator */
		if (!ed->txmit) {
			LLDPAD_WARN("%s:%s agent %d EVB Config disabled\n",
				__func__, ed->ifname, agent->type);
			return TLV_OK;
		}

		LLDPAD_DBG("%s:%s agent %d received tlv:\n", __func__,
			   port->ifname, agent->type);
		evb_dump_tlv(ed->ifname, tlv);
		memcpy(&ed->last, tlv->info, tlv->length);
		evb_print_tlvinfo(ed->ifname, &ed->last);

		evb_update_tlv(ed);
		somethingChangedLocal(ed->ifname, agent->type);

		LLDPAD_DBG("%s:%s agent %d new tlv:\n", __func__,
			   port->ifname, agent->type);
		evb_print_tlvinfo(ed->ifname, &ed->tie);
		vdp_update(port->ifname, ed->tie.ccap);
	}
	return TLV_OK;
}

/*
 * Stop all modules which depend on EVB capabilities.
 */
static void evb_stop_modules(char *ifname, struct lldp_agent *agent)
{
	LLDPAD_DBG("%s:%s agent %d STOP\n", __func__, ifname, agent->type);
	vdp_ifdown(ifname, agent);
}

static void evb_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct evb_data *ed;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return;
	LLDPAD_DBG("%s:%s agent %d called\n", __func__, ifname, agent->type);

	ed = evb_data(ifname, agent->type);
	if (!ed) {
		LLDPAD_DBG("%s:%s agent %d does not exist.\n", __func__,
			   ifname, agent->type);
		return;
	}

	if (ed->vdp_start)
		evb_stop_modules(ifname, agent);
	LIST_REMOVE(ed, entry);
	free(ed);
	LLDPAD_INFO("%s:%s agent %d removed\n", __func__, ifname, agent->type);
}

/*
 * Fill up evb structure with reasonable info from the configuration file.
 */
static void evb_init_tlv(struct evb_data *ed, struct lldp_agent *agent)
{
	memset(&ed->last, 0, sizeof ed->last);
	memset(&ed->tie, 0, sizeof ed->tie);
	memset(&ed->policy, 0, sizeof ed->policy);

	ed->txmit = evb_conf_enabletx(ed->ifname, agent->type);
	if (!ed->txmit)
		LLDPAD_DBG("%s:%s agent %d EVB tx is currently disabled\n",
			   __func__, ed->ifname, agent->type);

	hton24(ed->policy.oui, LLDP_MOD_EVB);
	/* Get fmode/capabilities/rte/vsi from configuration file into policy */
	ed->policy.smode = evb_conf_fmode(ed->ifname, agent->type);
	ed->policy.scap = evb_conf_capa(ed->ifname, agent->type);
	ed->policy.rte = evb_conf_rte(ed->ifname, agent->type);
	ed->policy.svsi = htons(evb_conf_vsis(ed->ifname, agent->type));
	ed->policy.cmode = 0;
	ed->policy.ccap = 0;

	hton24(ed->tie.oui, LLDP_MOD_EVB);
	ed->tie.smode = ed->policy.smode;
	ed->tie.cmode = 0;
	ed->tie.scap  = ed->policy.scap;
	ed->tie.ccap = 0;
	ed->tie.svsi = ed->policy.svsi;
	ed->tie.cvsi = 0;
	ed->tie.rte = ed->policy.rte;

	ed->last.smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD |
			  LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	evb_update_tlv(ed);
}

static void evb_ifup(char *ifname, struct lldp_agent *agent)
{
	struct evb_data *ed;
	struct evb_user_data *ud;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return;
	LLDPAD_DBG("%s:%s agent %d called\n", __func__, ifname, agent->type);

	ed = evb_data(ifname, agent->type);
	if (ed) {
		LLDPAD_DBG("%s:%s agent %d already exists\n", __func__, ifname,
			   agent->type);
		return;
	}

	/* not found, alloc/init per-port tlv data */
	ed = (struct evb_data *) calloc(1, sizeof(struct evb_data));
	if (!ed) {
		LLDPAD_ERR("%s:%s agent %d  malloc %zu failed\n",
			   __func__, ifname, agent->type, sizeof(*ed));
		return;
	}
	strncpy(ed->ifname, ifname, IFNAMSIZ);
	ed->agenttype = agent->type;

	evb_init_tlv(ed, agent);

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_EVB);
	LIST_INSERT_HEAD(&ud->head, ed, entry);
	LLDPAD_DBG("%s:%s agent %d added\n", __func__, ifname, agent->type);
}

static u8 evb_mibdelete(struct port *port, struct lldp_agent *agent)
{
	struct evb_data *ed;

	ed = evb_data(port->ifname, agent->type);
	if (ed && (agent->type == ed->agenttype)) {
		memset(&ed->last, 0, sizeof ed->last);
		vdp_update(port->ifname, 0);
	}
	return 0;
}

/*
 * Start all modules which depend on EVB capabilities: ECP, VDP, CDCP.
 */
static void evb_start_modules(char *ifname, struct lldp_agent *agent)
{
	LLDPAD_DBG("%s:%s agent %d START\n", __func__, ifname, agent->type);
	vdp_ifup(ifname, agent);
}

/*
 * Check for stable interfaces. When an interface goes up the carrier might
 * come and go during a start up time. Define a window during which the port
 * is considered unstable for EVB/VDP protocols.
 *
 * Use the dormantDelay counter of the port to determine a stable interface.
 */
int evb_timer(struct port *port, struct lldp_agent *agent)
{
	struct evb_data *ed;
	int bits = LLDP_EVB_CAPABILITY_PROTOCOL_ECP |
			LLDP_EVB_CAPABILITY_PROTOCOL_VDP;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb_data(port->ifname, agent->type);
	if (!ed)
		return 0;
	if (!ed->vdp_start &&
	    (port->dormantDelay == 1 || (bits & ed->tie.ccap) == bits)) {
		ed->vdp_start = true;
		evb_start_modules(port->ifname, agent);
		vdp_update(port->ifname, ed->tie.ccap);
	}
	return 0;
}

/*
 * Remove all interface/agent specific evb data.
 */
static void evb_free_data(struct evb_user_data *ud)
{
	struct evb_data *ed;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ed = LIST_FIRST(&ud->head);
			LIST_REMOVE(ed, entry);
			free(ed);
		}
	}
}

void evb_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		evb_free_data((struct evb_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done\n", __func__);
}

static const struct lldp_mod_ops evb_ops =  {
	.lldp_mod_register	= evb_register,
	.lldp_mod_unregister	= evb_unregister,
	.lldp_mod_gettlv	= evb_gettlv,
	.lldp_mod_rchange	= evb_rchange,
	.lldp_mod_ifup		= evb_ifup,
	.lldp_mod_ifdown	= evb_ifdown,
	.lldp_mod_mibdelete	= evb_mibdelete,
	.timer			= evb_timer,
	.get_arg_handler	= evb_get_arg_handlers
};

struct lldp_module *evb_register(void)
{
	struct lldp_module *mod;
	struct evb_user_data *ud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s: failed to malloc module data\n", __func__);
		return NULL;
	}
	ud = calloc(1, sizeof(struct evb_user_data));
	if (!ud) {
		free(mod);
		LLDPAD_ERR("%s failed to malloc module user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&ud->head);
	mod->id = LLDP_MOD_EVB;
	mod->ops = &evb_ops;
	mod->data = ud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;
}
