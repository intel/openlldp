/******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2012

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
#include "lldp_evb22.h"
#include "qbg_ecp22.h"
#include "qbg_vdp22.h"
#include "qbg_utils.h"
#include "lldp_evb_cmds.h"
#include "messages.h"
#include "config.h"

extern struct lldp_head lldp_head;

struct evb22_data *evb22_data(char *ifname, enum agent_type type)
{
	struct evb22_user_data *ud;
	struct evb22_data *ed = NULL;

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_EVB22);
	if (ud) {
		LIST_FOREACH(ed, &ud->head, entry) {
			if (!strncmp(ifname, ed->ifname, IFNAMSIZ) &&
			    (type == ed->agenttype))
				break;
		}
	}
	return ed;
}

static void evb22_format_tlv(char *buf, size_t len, struct evb22_tlv *tlv)
{
	int comma = 0;
	char bridge_txt[32], station_txt[32];

	memset(bridge_txt, 0, sizeof bridge_txt);
	if (evb_ex_bgid(tlv->bridge_s)) {
		strcat(bridge_txt, "bgid");
		comma = 1;
	}
	if (evb_ex_rrcap(tlv->bridge_s)) {
		if (comma)
			strcat(bridge_txt, ",");
		strcat(bridge_txt, "rrcap");
		comma = 1;
	}
	if (evb_ex_rrctr(tlv->bridge_s)) {
		if (comma)
			strcat(bridge_txt, ",");
		strcat(bridge_txt, "rrctr");
	}

	comma = 0;
	memset(station_txt, 0, sizeof station_txt);
	if (evb_ex_sgid(tlv->station_s)) {
		strcat(station_txt, "sgid");
		comma = 1;
	}
	if (evb_ex_rrreq(tlv->station_s)) {
		if (comma)
			strcat(station_txt, ",");
		strcat(station_txt, "rrreq");
		comma = 1;
	}
	if (evb_ex_rrstat(tlv->station_s)) {
		if (comma)
			strcat(station_txt, ",");
		strcat(station_txt, "rrstat");
	}
	snprintf(buf, len, "bridge:%s(%#02x) station:%s(%#02x) "
		    "retries:%d rte:%d mode:%d r/l:%d rwd:%d "
		    "r/l:%d rka:%d", bridge_txt, tlv->bridge_s,
		    station_txt, tlv->station_s,
		    evb_ex_retries(tlv->r_rte), evb_ex_rte(tlv->r_rte),
		    evb_ex_evbmode(tlv->evb_mode), evb_ex_rol(tlv->evb_mode),
		    evb_ex_rwd(tlv->evb_mode),
		    evb_ex_rol(tlv->rl_rka), evb_ex_rka(tlv->rl_rka));
}

static void evb22_print_tlvinfo(char *ifname, struct evb22_tlv *tlv)
{
	char buf[256];

	evb22_format_tlv(buf, sizeof buf, tlv);
	LLDPAD_DBG("%s evb %s\n", ifname, buf);
}

static void evb22_dump_tlv(char *ifname, struct unpacked_tlv *tlv)
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

static void common_tlv(struct evb22_data *ed)
{
	struct evb22_tlv *recv = &ed->last;
	struct evb22_tlv *mine = &ed->policy;
	u8 val;

	/* Set retries and rte value */
	val = evb_ex_retries(recv->r_rte);
	if (evb_ex_retries(mine->r_rte) > val)
		val = evb_ex_retries(mine->r_rte);
	ed->out.r_rte = evb_set_retries(val);
	val = evb_ex_rte(recv->r_rte);
	if (evb_ex_rte(mine->r_rte) > val)
		val = evb_ex_rte(mine->r_rte);
	ed->out.r_rte |= evb_set_rte(val);

	/* Set evbmode */
	ed->out.evb_mode = evb_set_evbmode(evb_ex_evbmode(mine->evb_mode));
	val = evb_ex_rwd(recv->evb_mode);
	if (evb_ex_rwd(mine->evb_mode) > val)
		val = evb_ex_rwd(mine->evb_mode);
	else
		ed->out.evb_mode |= evb_set_rol(1);
	ed->out.evb_mode |= evb_set_rwd(val);

	/* Set rka */
	ed->out.rl_rka = 0;
	val = evb_ex_rka(recv->rl_rka);
	if (evb_ex_rka(mine->rl_rka) > val)
		val = evb_ex_rka(mine->rl_rka);
	else
		ed->out.rl_rka = evb_set_rol(1);
	ed->out.rl_rka |= evb_set_rka(val);
}

/*
 * Fill the EVB DU for LLDP transmition. Sender is bridge.
 */
static void bridge_tlv(struct evb22_data *ed)
{
	struct evb22_tlv *recv = &ed->last;
	struct evb22_tlv *mine = &ed->policy;

	/* Copy my last station status */
	ed->out.station_s = recv->station_s;

	/* Set bridge status */
	ed->out.bridge_s = mine->bridge_s;
	if (evb_ex_rrreq(recv->station_s) && evb_ex_rrcap(mine->bridge_s))
		ed->out.bridge_s |= evb_set_rrctr(1);
	common_tlv(ed);
}

/*
 * Fill the EVB DU for LLDP transmition. Sender is station.
 */
static void station_tlv(struct evb22_data *ed)
{
	struct evb22_tlv *recv = &ed->last;
	struct evb22_tlv *mine = &ed->policy;
	u8 val;

	/* Copy my last bridge status */
	ed->out.bridge_s = recv->bridge_s;

	/*
	 * Set station status, 2nd byte of OUI is 0x80. If 0x00
	 * nothing received from bridge.
	 */
	if (recv->oui[1] == 0)
		val = EVB_RRSTAT_DONT;
	else if (evb_ex_rrctr(recv->bridge_s))
		val = EVB_RRSTAT_YES;
	else
		val = EVB_RRSTAT_NO;
	ed->out.station_s = evb_maskoff_rrstat(mine->station_s)
				| evb_set_rrstat(val);
	common_tlv(ed);
}

/*
 * Checks values received in TLV and takes over some values.
 * Sets the new suggestion in member tie to be send out to switch.
 *
 * Also notify depending modules about the new values.
 */
static void evb22_update_tlv(struct evb22_data *ed)
{
	struct qbg22_imm qbg;

	if (evb_ex_evbmode(ed->policy.evb_mode) == EVB_STATION)
		station_tlv(ed);
	else
		bridge_tlv(ed);

	qbg.data_type = EVB22_TO_ECP22;
	qbg.u.a.max_rte = evb_ex_rte(ed->out.r_rte);
	qbg.u.a.max_retry = evb_ex_retries(ed->out.r_rte);
	modules_notify(LLDP_MOD_ECP22, LLDP_MOD_EVB22, ed->ifname, &qbg);

	qbg.data_type = EVB22_TO_VDP22;
	qbg.u.b.max_rka = evb_ex_rka(ed->out.rl_rka);
	qbg.u.b.max_rwd = evb_ex_rwd(ed->out.evb_mode);
	qbg.u.b.max_rte = evb_ex_rte(ed->out.r_rte);
	qbg.u.b.max_retry = evb_ex_retries(ed->out.r_rte);
	/* Support group identifiers when advertised by both sides */
	qbg.u.b.gpid = evb_ex_bgid(ed->out.bridge_s)
		       && evb_ex_sgid(ed->out.station_s);
	qbg.u.b.evbon = ed->txmit;
	modules_notify(LLDP_MOD_VDP22, LLDP_MOD_EVB22, ed->ifname, &qbg);
}

/*
 * Build the packed EVB TLV.
 * Returns a pointer to the packed tlv or 0 on failure.
 */
static struct packed_tlv *evb22_build_tlv(struct evb22_data *ed)
{
	struct packed_tlv *ptlv = 0;
	u8 infobuf[sizeof(struct evb22_tlv)];
	struct unpacked_tlv tlv = {
		.type = ORG_SPECIFIC_TLV,
		.length = sizeof(struct evb22_tlv),
		.info = infobuf
	};

	evb22_update_tlv(ed);
	memcpy(tlv.info, &ed->out, tlv.length);
	ptlv = pack_tlv(&tlv);
	if (ptlv) {
		LLDPAD_DBG("%s:%s TLV about to be sent out:\n", __func__,
			   ed->ifname);
		evb22_dump_tlv(ed->ifname, &tlv);
	} else
		LLDPAD_DBG("%s:%s failed to pack EVB TLV\n", __func__,
			   ed->ifname);
	return ptlv;
}

/*
 * Function call to build and return module specific packed EVB TLV.
 * Returned packed_tlv is free'ed by caller of this function.
 */
static struct packed_tlv *evb22_gettlv(struct port *port,
				     struct lldp_agent *agent)
{
	struct evb22_data *ed;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb22_data(port->ifname, agent->type);
	if (!ed) {
		LLDPAD_ERR("%s:%s agent %d failed\n", __func__, port->ifname,
			   agent->type);
		return 0;
	}
	return (ed->txmit) ? evb22_build_tlv(ed) : 0;
}

/*
 * evb_rchange: process received EVB TLV LLDPDU
 *
 * TLV not consumed on error
 */
static int evb22_rchange(struct port *port, struct lldp_agent *agent,
		       struct unpacked_tlv *tlv)
{
	struct evb22_data *ed;
	u8 oui_subtype[OUI_SUB_SIZE] = LLDP_MOD_EVB22_OUI;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb22_data(port->ifname, agent->type);

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
		evb22_dump_tlv(ed->ifname, tlv);
		memcpy(&ed->last, tlv->info, tlv->length);
		evb22_print_tlvinfo(ed->ifname, &ed->last);

		evb22_update_tlv(ed);
		somethingChangedLocal(ed->ifname, agent->type);

		LLDPAD_DBG("%s:%s agent %d new tlv:\n", __func__, port->ifname,
			   agent->type);
		evb22_print_tlvinfo(ed->ifname, &ed->out);
		/* TODO vdp_update(port->ifname, ed->tie.ccap); */
	}
	return TLV_OK;
}

/*
 * Stop all modules which depend on EVB capabilities.
 */
static void evb22_stop_modules(char *ifname)
{
	LLDPAD_DBG("%s:%s STOP\n", __func__, ifname);
	ecp22_stop(ifname);
	vdp22_stop(ifname);
}

static void evb22_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct evb22_data *ed;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return;
	LLDPAD_DBG("%s:%s agent %d called\n", __func__, ifname, agent->type);

	ed = evb22_data(ifname, agent->type);
	if (!ed) {
		LLDPAD_DBG("%s:%s agent %d does not exist.\n", __func__,
			   ifname, agent->type);
		return;
	}
	if (ed->vdp_start)
		evb22_stop_modules(ifname);
	LIST_REMOVE(ed, entry);
	free(ed);
	LLDPAD_INFO("%s:%s agent %d removed\n", __func__, ifname, agent->type);
}

/*
 * Fill up evb structure with reasonable info from the configuration file.
 */
static void evb22_init_tlv(struct evb22_data *ed, struct lldp_agent *agent)
{
	u8 mode;

	memset(&ed->last, 0, sizeof ed->last);
	memset(&ed->out, 0, sizeof ed->out);
	memset(&ed->policy, 0, sizeof ed->policy);

	ed->txmit = evb22_conf_enabletx(ed->ifname, agent->type);
	if (!ed->txmit)
		LLDPAD_DBG("%s:%s agent %d EVB tx is currently disabled\n",
			   __func__, ed->ifname, agent->type);

	hton24(ed->policy.oui, LLDP_MOD_EVB22);
	ed->policy.sub = LLDP_MOD_EVB22_SUBTYPE;
	hton24(ed->out.oui, LLDP_MOD_EVB22);
	ed->out.sub = LLDP_MOD_EVB22_SUBTYPE;

	mode = evb22_conf_evbmode(ed->ifname, agent->type);
	ed->policy.evb_mode = evb_set_rol(0)
		| evb_set_rwd(evb22_conf_rwd(ed->ifname, agent->type))
		| evb_set_evbmode(mode);
	if (mode  == EVB_STATION) {
		mode = evb22_conf_rrreq(ed->ifname, agent->type);
		ed->policy.station_s = evb_set_rrstat(EVB_RRSTAT_DONT)
			| evb_set_sgid(evb22_conf_gid(ed->ifname, agent->type))
			| evb_set_rrreq(mode);
		ed->policy.bridge_s = 0;
	} else {
		mode = evb22_conf_rrcap(ed->ifname, agent->type);
		ed->policy.bridge_s = evb_set_rrcap(mode)
			| evb_set_bgid(evb22_conf_gid(ed->ifname, agent->type));
		ed->policy.station_s = 0;
	}
	ed->policy.r_rte =
		evb_set_retries(evb22_conf_retries(ed->ifname, agent->type))
		| evb_set_rte(evb22_conf_rte(ed->ifname, agent->type));
	ed->policy.rl_rka = evb_set_rol(0)
		| evb_set_rka(evb22_conf_rka(ed->ifname, agent->type));
}

static void evb22_ifup(char *ifname, struct lldp_agent *agent)
{
	struct evb22_data *ed;
	struct evb22_user_data *ud;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return;
	LLDPAD_DBG("%s:%s agent %d called\n", __func__, ifname, agent->type);
	if (is_tlv_txenabled(ifname, agent->type,
			     TLVID(OUI_IEEE_8021Qbg, LLDP_EVB_SUBTYPE))) {
		LLDPAD_ERR("%s:%s evb draft 0.2 protocol already enabled\n",
			   __func__, ifname);
		return;
	}

	ed = evb22_data(ifname, agent->type);
	if (ed) {
		LLDPAD_DBG("%s:%s agent %d already exists\n", __func__, ifname,
			   agent->type);
		return;
	}

	/* not found, alloc/init per-port tlv data */
	ed = (struct evb22_data *) calloc(1, sizeof *ed);
	if (!ed) {
		LLDPAD_ERR("%s:%s agent %d malloc %zu failed\n",
			   __func__, ifname, agent->type, sizeof *ed);
		return;
	}
	strncpy(ed->ifname, ifname, IFNAMSIZ);
	ed->agenttype = agent->type;
	evb22_init_tlv(ed, agent);
	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_EVB22);
	LIST_INSERT_HEAD(&ud->head, ed, entry);
	LLDPAD_DBG("%s:%s agent %d added\n", __func__, ifname, agent->type);
}

/*
 * Start all modules which depend on EVB capabilities: ECP, VDP, CDCP.
 */
static void evb22_start_modules(char *ifname, int role)
{
	LLDPAD_DBG("%s:%s START role:%d\n", __func__, ifname, role);
	ecp22_start(ifname);
	vdp22_start(ifname, role);
}

/*
 * Check for stable interfaces. When an interface goes up the carrier might
 * come and go during a start up time. Define a window during which the port
 * is considered unstable for EVB/VDP protocols.
 *
 * Use the dormantDelay counter of the port to determine a stable interface.
 */
static int evb22_timer(struct port *port, struct lldp_agent *agent)
{
	struct evb22_data *ed;

	if (agent->type != NEAREST_CUSTOMER_BRIDGE)
		return 0;
	ed = evb22_data(port->ifname, agent->type);
	if (!ed)
		return 0;
	if (!ed->vdp_start) {
		ed->vdp_start = true;
		evb22_start_modules(port->ifname,
				    evb_ex_evbmode(ed->policy.evb_mode));
	}
	return 0;
}

static u8 evb22_mibdelete(struct port *port, struct lldp_agent *agent)
{
	struct evb22_data *ed;

	ed = evb22_data(port->ifname, agent->type);
	if (ed && (agent->type == ed->agenttype)) {
		memset(&ed->last, 0, sizeof ed->last);
		/* TODO vdp_update(port->ifname, 0); */
	}
	return 0;
}

/*
 * Remove all interface/agent specific evb data.
 */
static void evb22_free_data(struct evb22_user_data *ud)
{
	struct evb22_data *ed;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ed = LIST_FIRST(&ud->head);
			LIST_REMOVE(ed, entry);
			free(ed);
		}
	}
}

void evb22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		evb22_free_data((struct evb22_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done\n", __func__);
}

static const struct lldp_mod_ops evb22_ops =  {
	.lldp_mod_gettlv	= evb22_gettlv,
	.lldp_mod_rchange	= evb22_rchange,
	.lldp_mod_mibdelete	= evb22_mibdelete,
	.timer			= evb22_timer,
	.lldp_mod_ifdown	= evb22_ifdown,
	.lldp_mod_ifup		= evb22_ifup,
	.lldp_mod_register	= evb22_register,
	.lldp_mod_unregister	= evb22_unregister,
	.get_arg_handler	= evb22_get_arg_handlers
};

struct lldp_module *evb22_register(void)
{
	struct lldp_module *mod;
	struct evb22_user_data *ud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s: failed to malloc module data\n", __func__);
		return NULL;
	}
	ud = calloc(1, sizeof *ud);
	if (!ud) {
		free(mod);
		LLDPAD_ERR("%s failed to malloc module user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&ud->head);
	mod->id = LLDP_MOD_EVB22;
	mod->ops = &evb22_ops;
	mod->data = ud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;
}
