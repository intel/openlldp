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

#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_bridge.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "lldp.h"
#include "lldp_tlv.h"
#include "lldp_evb.h"
#include "lldp_vdp.h"
#include "messages.h"
#include "config.h"
#include "lldp_mand_clif.h"
#include "lldp_evb_clif.h"
#include "lldp_evb_cmds.h"


extern struct lldp_head lldp_head;
extern int vdp_vsis(char *ifname);

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

static void evb_print_tlvinfo(struct tlv_info_evb *tlv)
{
	LLDPAD_INFO("EVB supported/configured forwarding mode: %#02x/%#02x "
		    "capabilities: %#02x/%#02x vsis: %04i/%04i "
		    "rte: %02i\n",
		    tlv->smode, tlv->cmode, tlv->scap, tlv->ccap,
		    ntohs(tlv->svsi), ntohs(tlv->cvsi), tlv->rte);
}

static void evb_dump_tlv(struct unpacked_tlv *tlv)
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

	LLDPAD_DBG("%s:type %i length %i info %s\n",
		   __func__, tlv->type, tlv->length, buffer);
}

/* evb_check_and_fill
 *
 * checks values received in TLV and takes over some values
 */
static int evb_check_and_fill(struct evb_data *ed, struct tlv_info_evb *tie)
{
	/* sanity check of received data in tie */
	if ((tie->smode & (LLDP_EVB_CAPABILITY_FORWARD_STANDARD |
			  LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)) == 0) {
		LLDPAD_ERR("Neither standard nor rr set as forwarding modes\n");
		return TLV_ERR;
	}

	/* check bridge capabilities against local policy*/
	/* if bridge supports RR and we support it as well, request it
	 * by setting smode in tlv to be sent out (ed->tie->smode) */
	if ((tie->smode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY) &&
	    (ed->policy->smode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY))
		ed->tie->smode = LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	else
		ed->tie->smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;

	/* maybe switch has already set the mode based on the saved info sent
	 * out on ifup */
	if (tie->cmode == ed->tie->smode)
		ed->tie->cmode = tie->cmode;

	ed->tie->scap = ed->policy->scap;

	/* If both sides support RTE, support and configure it */
	if ((tie->scap & ed->policy->scap) & LLDP_EVB_CAPABILITY_PROTOCOL_RTE)
		ed->tie->ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_RTE;
	else
		ed->tie->ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_RTE;

	/* If both sides support ECP, set it */
	if ((tie->scap & ed->policy->scap) & LLDP_EVB_CAPABILITY_PROTOCOL_ECP)
		ed->tie->ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_ECP;
	else
		ed->tie->ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_ECP;

	/* If both sides support VDP, set it */
	if ((tie->scap & ed->policy->scap) & LLDP_EVB_CAPABILITY_PROTOCOL_VDP)
		ed->tie->ccap |= LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
	else
		ed->tie->ccap &= ~LLDP_EVB_CAPABILITY_PROTOCOL_VDP;

	/* If supported caps include VDP take over min value of both */
	if (ed->tie->scap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP) {
		ed->tie->svsi = tie->svsi;
		ed->tie->cvsi = htons(vdp_vsis(ed->ifname));
	} else {
		ed->tie->svsi = 0;
		ed->tie->cvsi = 0;
	}

	/* If both sides support RTE and value offer is > 0, set it */
	if ((ed->tie->scap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE) &&
		(tie->rte > 0) && (ed->policy->rte > 0))
		ed->tie->rte = MAX(ed->policy->rte, tie->rte);

	return TLV_OK;
}

/* evb_process_tlv - processes the tlv
 * @ed: evb_data for the interface
 * @tie: incoming tlv
 *
 * checks the received tlv and takes over values as needed.
 *
 */
static void evb_update_tlv(struct evb_data *ed)
{
	/* waiting for valid packets to pour in
	 * if valid packet was received,
	 * - check parameters with what we have offered for this if,
	 * - fill structure with data,
	 * - enable local tx
	 */
	if (evb_check_and_fill(ed, ed->last) != TLV_OK)
		LLDPAD_ERR("Invalid contents of EVB Cfg TLV\n");
}

/*
 * evb_bld_cfg_tlv - build the EVB TLV
 * @ed: the evb data struct
 *
 * Returns 0 on success
 */
static int evb_bld_cfg_tlv(struct evb_data *ed, struct lldp_agent *agent)
{
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;

	/* free ed->evb if it exists */
	FREE_UNPKD_TLV(ed, evb);

	if (!is_tlv_txenabled(ed->ifname, agent->type,
			      TLVID_8021Qbg(LLDP_EVB_SUBTYPE))) {
		LLDPAD_DBG("%s:%s:EVB tx is currently disabled\n",
			__func__, ed->ifname);
		rc = EINVAL;
		goto out_err;
	}

	if (ed->tie->smode != ed->policy->smode)
		ed->tie->smode = ed->policy->smode;

	evb_update_tlv(ed);

	tlv = create_tlv();
	if (!tlv) {
		rc = ENOMEM;
		goto out_err;
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct tlv_info_evb);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		rc = ENOMEM;
		goto out_err;
	}
	memcpy(tlv->info, ed->tie, tlv->length);

	LLDPAD_DBG("%s: TLV about to be sent out:\n", __func__);
	evb_dump_tlv(tlv);

	ed->evb = tlv;
out_err:
	return rc;
}

static void evb_free_tlv(struct evb_data *ed)
{
	if (ed)
		FREE_UNPKD_TLV(ed, evb);
}

/* evb_init_cfg_tlv:
 *
 * fill up tlv_info_evb structure with reasonable info
 */
static int evb_init_cfg_tlv(struct evb_data *ed, struct lldp_agent *agent)
{

	/* load policy from config */
	ed->policy = calloc(1, sizeof(struct tlv_info_evb));

	if (!ed->policy)
		return ENOMEM;

	/* set defaults */
	hton24(ed->policy->oui, LLDP_MOD_EVB);
	ed->policy->smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;
	ed->policy->scap = LLDP_EVB_CAPABILITY_PROTOCOL_RTE |
			   LLDP_EVB_CAPABILITY_PROTOCOL_ECP |
			   LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
	ed->policy->cmode = 0;
	ed->policy->ccap = 0;
	ed->policy->svsi = htons(LLDP_EVB_DEFAULT_SVSI);
	ed->policy->rte = LLDP_EVB_DEFAULT_RTE;

	ed->txmit = evb_conf_enabletx(ed->ifname, agent->type);
	/* Get fmode/capabilities/rte/vsi from configuration file into policy */
	ed->policy->smode = evb_conf_fmode(ed->ifname, agent->type);
	ed->policy->scap = evb_conf_capa(ed->ifname, agent->type);
	ed->policy->rte = evb_conf_rte(ed->ifname, agent->type);
	ed->policy->svsi = htons(evb_conf_vsis(ed->ifname, agent->type));

	ed->tie = (struct tlv_info_evb *)
			calloc(1, sizeof(struct tlv_info_evb));

	if (!ed->tie) {
		free(ed->policy);
		ed->policy = NULL;
		return ENOMEM;
	}

	hton24(ed->tie->oui, LLDP_MOD_EVB);
	ed->tie->smode = ed->policy->smode;
	ed->tie->cmode = 0x0;
	ed->tie->scap  = ed->policy->scap;
	ed->tie->ccap = 0x0;
	ed->tie->svsi = htons(LLDP_EVB_DEFAULT_SVSI);
	ed->tie->cvsi = htons(0x0);
	ed->tie->rte = LLDP_EVB_DEFAULT_RTE;

	LLDPAD_INFO("%s:%s: filling last used EVB TLV, using default\n",
		__func__, ed->ifname);
	ed->last = (struct tlv_info_evb *)
			calloc(1, sizeof(struct tlv_info_evb));

	if (!ed->last) {
		free(ed->policy);
		free(ed->tie);
		ed->policy = NULL;
		ed->tie = NULL;
		return ENOMEM;
	}

	ed->last->smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD |
			  LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	return 0;
}

static int evb_bld_tlv(struct evb_data *ed, struct lldp_agent *agent)
{
	int rc = 0;

	if (!port_find_by_name(ed->ifname)) {
		rc = EEXIST;
		return rc;
	}

	if (evb_bld_cfg_tlv(ed, agent)) {
		LLDPAD_DBG("%s:%s:evb_bld_cfg_tlv() failed\n",
				__func__, ed->ifname);
		rc = EINVAL;
	}
	return rc;
}

static void evb_free_data(struct evb_user_data *ud)
{
	struct evb_data *ed;
	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ed = LIST_FIRST(&ud->head);
			LIST_REMOVE(ed, entry);

			free(ed->tie);
			free(ed->last);
			free(ed->policy);
			evb_free_tlv(ed);

			free(ed);
		}
	}
}

static struct packed_tlv *evb_gettlv(struct port *port,
		struct lldp_agent *agent)
{
	int size;
	struct evb_data *ed;
	struct packed_tlv *ptlv = NULL;

	ed = evb_data(port->ifname, agent->type);
	if (!ed)
		goto out_err;

	evb_free_tlv(ed);

	if (evb_bld_tlv(ed, agent)) {
		LLDPAD_DBG("%s:%s evb_bld_tlv failed\n",
			__func__, port->ifname);
		goto disabled;
	}

	size = TLVSIZE(ed->evb);

	if (!size)
		goto out_err;

	ptlv = create_ptlv();
	if (!ptlv)
		goto out_err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	ptlv->size = 0;
	PACK_TLV_AFTER(ed->evb, ptlv, size, out_free);
disabled:
	return ptlv;
out_free:
	/* FIXME: free function returns pointer ? */
	ptlv = free_pkd_tlv(ptlv);
out_err:
	LLDPAD_ERR("%s:%s: failed\n", __func__, port->ifname);
	return NULL;
}

static void update_vdp_module(char *ifname, u8 ccap)
{
	struct vdp_data *vdp = vdp_data(ifname);

	if (vdp) {
		vdp->vdpbit_on = ccap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
		LLDPAD_DBG("%s vdpbit_on %d\n", __func__, vdp->vdpbit_on);
	}
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

		LLDPAD_DBG("%s: %s agent %d received tlv:\n", __func__,
			   port->ifname, agent->type);
		evb_dump_tlv(tlv);
		memcpy(ed->last, tlv->info, tlv->length);
		evb_print_tlvinfo(ed->last);

		evb_update_tlv(ed);
		somethingChangedLocal(ed->ifname, agent->type);

		LLDPAD_DBG("%s: %s agent %d new tlv:\n", __func__,
			   port->ifname, agent->type);
		evb_print_tlvinfo(ed->tie);
		update_vdp_module(port->ifname, ed->tie->ccap);
	}
	return TLV_OK;
}

static void evb_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct evb_data *ed;

	LLDPAD_DBG("%s port %s agent %d called\n", __func__, ifname,
		   agent->type);

	ed = evb_data(ifname, agent->type);
	if (!ed) {
		LLDPAD_DBG("%s:port %s agent %d does not exist.\n", __func__,
			   ifname, agent->type);
		return;
	}

	free(ed->policy);
	free(ed->tie);
	free(ed->last);
	LIST_REMOVE(ed, entry);
	evb_free_tlv(ed);
	free(ed);
	LLDPAD_INFO("%s:port %s agent %d removed\n", __func__, ifname,
		    agent->type);
}

static void evb_ifup(char *ifname, struct lldp_agent *agent)
{
	struct evb_data *ed;
	struct evb_user_data *ud;

	LLDPAD_DBG("%s port %s agent %d called\n", __func__, ifname,
		   agent->type);

	ed = evb_data(ifname, agent->type);
	if (ed) {
		LLDPAD_DBG("%s:%s already exists\n", __func__, ifname);
		return;
	}

	/* not found, alloc/init per-port tlv data */
	ed = (struct evb_data *) calloc(1, sizeof(struct evb_data));
	if (!ed) {
		LLDPAD_ERR("%s:%s malloc %zu failed\n",
			   __func__, ifname, sizeof(*ed));
		return;
	}
	strncpy(ed->ifname, ifname, IFNAMSIZ);
	ed->agenttype = agent->type;

	if (evb_init_cfg_tlv(ed, agent)) {
		LLDPAD_ERR("%s:%s failed\n", __func__, ifname);
		goto out_free;
	}

	evb_bld_tlv(ed, agent);

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_EVB);
	LIST_INSERT_HEAD(&ud->head, ed, entry);
	LLDPAD_DBG("%s:port %s agent %d added\n", __func__, ifname,
		   agent->type);
	return;

out_free:
	free(ed->tie);
	free(ed->last);
	free(ed->policy);
	free(ed);
}

static u8 evb_mibdelete(struct port *port, struct lldp_agent *agent)
{
	struct evb_data *ed;

	if (!is_tlv_txenabled(port->ifname, agent->type,
			      TLVID_8021Qbg(LLDP_EVB_SUBTYPE))) {
		goto out_err;
	}

	ed = evb_data(port->ifname, agent->type);
	if (!ed) {
		LLDPAD_DBG("%s: port %s agent %d does not exist.\n", __func__,
			   port->ifname, agent->type);
		goto out_err;
	}

	free(ed->tie);
	free(ed->last);
	free(ed->policy);

	if (evb_init_cfg_tlv(ed, agent))
		LLDPAD_ERR("%s:%s agent %d evb_init_cfg_tlv failed\n", __func__,
			   port->ifname, agent->type);
	else
		evb_bld_tlv(ed, agent);

out_err:
	return 0;
}

static const struct lldp_mod_ops evb_ops =  {
	.lldp_mod_register	= evb_register,
	.lldp_mod_unregister	= evb_unregister,
	.lldp_mod_gettlv	= evb_gettlv,
	.lldp_mod_rchange	= evb_rchange,
	.lldp_mod_ifup		= evb_ifup,
	.lldp_mod_ifdown	= evb_ifdown,
	.lldp_mod_mibdelete	= evb_mibdelete,
	.get_arg_handler	= evb_get_arg_handlers,
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

void evb_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		evb_free_data((struct evb_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done", __func__);
}
