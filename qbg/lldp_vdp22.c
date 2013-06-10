/******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2013

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
#include <string.h>
#include <errno.h>
#include <string.h>

#include <net/if.h>

#include "messages.h"
#include "config.h"

#include "lldp_mod.h"
#include "lldp_util.h"
#include "lldp_vdpnl.h"
#include "lldp_qbg22.h"
#include "lldp_vdp22.h"
#include "qbg_utils.h"

/*
 * VDP22 helper functions
 */

/*
 * Print a profile.
 */
void vdp22_showprof(struct vsi22_profile *p)
{
	char uuid[VDP_UUID_STRLEN + 2];
	struct vdp22_mac_vlan *mac_vlan;

	vdp_uuid2str(p->uuid, uuid, sizeof(uuid));
	LLDPAD_DBG("profile:%p mode:%d response:%d"
		   " mgrid:%d id:%d(%#x) version:%d %s format:%d entries:%d\n",
		   p, p->req_mode, p->req_response, p->mgrid, p->typeid,
		    p->typeid, p->typeid_ver, uuid, p->format, p->entries);
	LIST_FOREACH(mac_vlan, &p->macvid_head, node) {
		mac2str(mac_vlan->mac, uuid, sizeof uuid);
		LLDPAD_DBG("profile:%p mac:%s vlan:%d qos:%d pid:%d seq:%ld\n",
			   p, uuid, mac_vlan->vlan, mac_vlan->qos,
			   mac_vlan->req_pid, mac_vlan->req_seq);
	}
}

/*
 * vdp22_remove_macvlan - remove all mac/vlan pairs in the profile
 *
 * Remove all allocated <mac,vlan> pairs on the profile.
*/
static void vdp22_remove_macvlan(struct vsi22_profile *p)
{
	struct vdp22_mac_vlan *macp;

	while ((macp = LIST_FIRST(&p->macvid_head))) {
		LIST_REMOVE(macp, node);
		free(macp);
	}
}

/*
 * Delete a complete profile node
 */
static void vdp22_delete_prof(struct vsi22_profile *prof)
{
	vdp22_remove_macvlan(prof);
	free(prof);
}

/*
 * Remove a profile node from list and delete it
 */
static void vdp22_listdel_prof(struct vsi22_profile *prof)
{
	LLDPAD_DBG("%s:%s profile:%p(%02x)\n", __func__, prof->ifname,
		   prof, prof->uuid[PUMLAST]);
	LIST_REMOVE(prof, prof22_node);
	vdp22_delete_prof(prof);
}

static bool check_macvlan(struct vdp22_mac_vlan *macp)
{
	if (macp->vlan < 2 || macp->vlan > 4094)
		return false;
	if (!is_valid_mac(macp->mac))
		return false;
	return true;
}

/* Check for valid VSI request mode */
static bool check_vsi(struct vdpnl_vsi *vsi)
{
	switch (vsi->request) {
	case VDP22_PREASSOC:
	case VDP22_PREASSOC_WITH_RR:
	case VDP22_ASSOC:
	case VDP22_DEASSOC:
	case VDP22_MGRID:
	case VDP22_OUI:	return true;
	}
	return false;
}

/*
 * Allocate a vsi_profile with MAC/VLAN list
 */
static struct vsi22_profile *vdp22_alloc_prof(struct vdpnl_vsi *vsi, int *rc)
{
	struct vsi22_profile *p;
	int i;

	*rc = -EINVAL;
	if (!check_vsi(vsi))
		return NULL;
	p = calloc(1, sizeof *p);
	if (!p) {
		*rc = -ENOMEM;
		 return p;
	}
	LIST_INIT(&p->macvid_head);
	strncpy(p->ifname, vsi->ifname, sizeof p->ifname);
	/* Adjust new numbering for VDP22 protocol */
	p->req_mode = 1 + vsi->request;
	p->req_response = VDP22_RESP_NONE;
	p->mgrid = vsi->vsi_mgrid;
	p->typeid_ver = vsi->vsi_typeversion;
	p->typeid = vsi->vsi_typeid;
	memcpy(p->uuid, vsi->vsi_uuid, sizeof p->uuid);
	p->format = vsi->filter_fmt;
	p->entries = vsi->macsz;

	for (i = 0; i < vsi->macsz; ++i) {
		struct vdpnl_mac *from = &vsi->maclist[i];
		struct vdp22_mac_vlan *macp;

		macp = calloc(1, sizeof *macp);
		if (!macp) {
			*rc = -ENOMEM;
			goto error1;
		}
		LIST_INSERT_HEAD(&p->macvid_head, macp, node);
		memcpy(macp->mac, from->mac, sizeof macp->mac);
		macp->qos = from->qos;
		macp->vlan = from->vlan;
		macp->req_pid = vsi->req_pid;
		macp->req_seq = vsi->req_seq;
		if (!check_macvlan(macp)) {
			*rc = -EINVAL;
			goto error1;
		}
	}
	*rc = 0;
	LLDPAD_DBG("%s:%s profile:%p(%02x)\n", __func__, vsi->ifname,
		   p, p->uuid[PUMLAST]);
	return p;
error1:
	vdp22_delete_prof(p);
	return NULL;
}

/*
 * Find the vdp data associated with an interface.
 * Parameter 'ud' may be zero, then search for the module first.
 *
 * Return pointer or NULL if not found.
 */
static struct vdp22 *vdp22_findif(const char *ifname,
				  struct vdp22_user_data *ud)
{
	struct vdp22 *vdp = 0;

	if (!ud) {
		ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
		if (!ud)
			LLDPAD_DBG("%s:%s no VDP22 module\n", __func__,
				   ifname);
	}
	if (ud) {
		LIST_FOREACH(vdp, &ud->head, entry)
			if (!strncmp(ifname, vdp->ifname, IFNAMSIZ))
				break;
	}
	return vdp;
}

/*
 * Update data exchanged via ECP protocol.
 * Returns true when data update succeeded.
 */
static int data_from_ecp(char *ifname, struct ecp22_to_ulp *ptr)
{
	struct vdp22 *vdp;

	vdp = vdp22_findif(ifname, NULL);
	if (vdp) {
		memcpy(vdp->input, ptr->data, ptr->len);
		vdp->input_len = ptr->len;
		return 0;
	}
	return -ENOENT;
}

/*
 * Update data exchanged via EVB protocol.
 * Calculate the various time out values based in input parameters.
 * See IEEE 802.1Qbg ratified standard 41.5.5.7 + 41.5.5.9
 * Returns true when data update succeeded.
 */
static int data_from_evb(char *ifname, struct evb22_to_vdp22 *ptr)
{
	int rc = -ENOENT;
	struct vdp22 *vdp;

	vdp = vdp22_findif(ifname, NULL);
	if (vdp) {
		vdp->wdly_us = (1 << ptr->max_rwd) * 10;
		vdp->resp_us = (1 + 2 * ptr->max_retry)
				* (1 << ptr->max_rte) * 10;
		vdp->ka_us = (1 << ptr->max_rka) * 10;
		vdp->gpid = ptr->gpid;
		LLDPAD_DBG("%s:%s rwd:%d rka:%d gpid:%d retry:%d rte:%d"
			   " waitdelay:%lld respdelay:%lld keepalive:%lld\n",
			   __func__, ifname, ptr->max_rwd, ptr->max_rka,
			   ptr->gpid, ptr->max_retry, ptr->max_rte,
			   vdp->wdly_us, vdp->resp_us, vdp->ka_us);
		rc = 0;
	}
	return rc;
}

/*
 * Handle notifications from other modules. Check if sender-id and data type
 * indicator match. Return false when data could not be delivered.
 */
static int vdp22_notify(int sender_id, char *ifname, void *data)
{
	struct qbg22_imm *qbg = (struct qbg22_imm *)data;

	LLDPAD_DBG("%s:%s sender-id:%#x data_type:%d\n", __func__, ifname,
		   sender_id, qbg->data_type);
	if (sender_id == LLDP_MOD_EVB22 && qbg->data_type == EVB22_TO_VDP22)
		return data_from_evb(ifname, &qbg->u.b);
	if (sender_id == LLDP_MOD_ECP22 && qbg->data_type == ECP22_TO_ULP)
		return data_from_ecp(ifname, &qbg->u.c);
	return 0;
}

/*
 * Remove a vdp22 element and delete the chain of active profiles.
 */
static void vdp22_free_elem(struct vdp22 *vdp)
{
	while (!LIST_EMPTY(&vdp->prof22_head)) {
		struct vsi22_profile *prof = LIST_FIRST(&vdp->prof22_head);

		free(prof);
	}
	LIST_REMOVE(vdp, entry);
	free(vdp);
}

/*
 * Disable the interface for VDP protocol support.
 */
void vdp22_stop(char *ifname)
{
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;

	LLDPAD_DBG("%s:%s stop vdp\n", __func__, ifname);
	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	if (!vud) {
		LLDPAD_ERR("%s:%s no VDP22 module\n", __func__, ifname);
		return;
	}
	vdp = vdp22_findif(ifname, vud);
	if (!vdp) {
		LLDPAD_ERR("%s:%s no VDP22 data\n", __func__, ifname);
		return;
	}
	vdp22_free_elem(vdp);
}

/*
 * vdp22_create - create data structure and initialize vdp protocol
 * @ifname: interface for which the vdp protocol is initialized
 *
 * returns NULL on error and an pointer to the vdp22 structure on success.
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming vdp frames and initializes the vdp rx and tx state machines.
 * To be called when a successful exchange of EVB TLVs has been
 * made and ECP protocols are supported by both sides.
 */
static struct vdp22 *vdp22_create(const char *ifname,
				  struct vdp22_user_data *eud)
{
	struct vdp22 *vdp;

	vdp = calloc(1, sizeof *vdp);
	if (!vdp) {
		LLDPAD_ERR("%s:%s unable to allocate vdp protocol\n", __func__,
			   ifname);
		return NULL;
	}
	strncpy(vdp->ifname, ifname, sizeof vdp->ifname);
	LIST_INIT(&vdp->prof22_head);
	LIST_INSERT_HEAD(&eud->head, vdp, entry);
	LLDPAD_DBG("%s:%s create vdp data\n", __func__, ifname);
	return vdp;
}

/*
 * Query the supported VDP protocol on an interface.
 */
static struct vdp22 *vdp22_getvdp(const char *ifname)
{
	struct vdp22 *vdp = NULL;

	vdp = vdp22_findif(ifname, NULL);
	LLDPAD_DBG("%s:%s vdp %p\n", __func__, ifname, vdp);
	return vdp;
}

int vdp22_query(const char *ifname)
{
	int rc = 0;

	if (vdp22_getvdp(ifname))
		rc = 1;
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, ifname, rc);
	return rc;
}

/*
 * Enable the interface for VDP protocol support.
 */
void vdp22_start(const char *ifname)
{
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;

	LLDPAD_DBG("%s:%s start vdp\n", __func__, ifname);
	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	if (!vud) {
		LLDPAD_ERR("%s:%s no VDP22 module\n", __func__, ifname);
		return;
	}
	vdp = vdp22_findif(ifname, vud);
	if (!vdp)
		vdp = vdp22_create(ifname, vud);
}

/*
 * Handle a VSI request from buddy.
 */
int vdp22_request(struct vdpnl_vsi *vsi)
{
	int rc;
	struct vsi22_profile *p;
	struct vdp22 *vdp;

	LLDPAD_DBG("%s:%s\n", __func__, vsi->ifname);
	vdp = vdp22_findif(vsi->ifname, NULL);
	if (vdp) {
		p = vdp22_alloc_prof(vsi, &rc);
		if (p)
			rc = vdp22_addreq(p, vdp);
	} else
		rc = -ENODEV;
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, vsi->ifname, rc);
	return rc;
}

/*
 * Remove all interface/agent specific vdp data.
 */
static void vdp22_free_data(struct vdp22_user_data *ud)
{
	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			struct vdp22 *vd = LIST_FIRST(&ud->head);

			vdp22_free_elem(vd);
		}
	}
}

void vdp22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		vdp22_free_data((struct vdp22_user_data *)mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done\n", __func__);
}

static const struct lldp_mod_ops vdp22_ops =  {
	.lldp_mod_register	= vdp22_register,
	.lldp_mod_unregister	= vdp22_unregister,
	.lldp_mod_notify	= vdp22_notify
};

struct lldp_module *vdp22_register(void)
{
	struct lldp_module *mod;
	struct vdp22_user_data *ud;

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
	mod->id = LLDP_MOD_VDP22;
	mod->ops = &vdp22_ops;
	mod->data = ud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;
}

/*
 * Query a VSI request from buddy and report its progress. Use the interface
 * name to determine the VSI profile list. Return one entry in parameter 'vsi'
 * use the structure members response and vsi_uuid.
 * Returns
 * 1  valid VSI data returned
 * 0  end of queue (no VSI data returned)
 * <0 errno
 */
int vdp22_status(int number, struct vdpnl_vsi *vsi)
{
	struct vdp22 *vdp;
	struct vsi22_profile *p;
	int i = 0, ret = 0;

	LLDPAD_DBG("%s:%s\n", __func__, vsi->ifname);
	vdp = vdp22_findif(vsi->ifname, NULL);
	if (!vdp) {
		LLDPAD_ERR("%s: %s has not yet been configured\n", __func__,
			   vsi->ifname);
		return -ENODEV;
	}
	/* Interate to queue element number */
	LIST_FOREACH(p, &vdp->prof22_head, prof22_node) {
		if (++i == number) {
			ret = 1;
			break;
		}
	}
	if (ret) {
		vdp22_showprof(p);
		vsi->response = p->req_response;
		memcpy(vsi->vsi_uuid, p->uuid, sizeof vsi->vsi_uuid);
		if (p->req_response != VDP22_RESP_NONE && p->done)
			vdp22_listdel_prof(p);
	}
	LLDPAD_DBG("%s: entry:%d more:%d\n", __func__, number, ret);
	return ret;
}
