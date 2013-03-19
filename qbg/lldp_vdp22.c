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
#include <errno.h>

#include <net/if.h>

#include "messages.h"
#include "config.h"

#include "lldp_vdpnl.h"
#include "lldp_qbg22.h"
#include "lldp_vdp22.h"

/*
 * VDP22 helper functions
 */
/*
 * Find the vdp data associated with an interface.
 * Return pointer or NULL if not found.
 */
static struct vdp22 *vdp22_findif(const char *ifname,
				  struct vdp22_user_data *ud)
{
	struct vdp22 *vdp = 0;

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
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;

	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	vdp = vdp22_findif(ifname, vud);
	if (vdp) {
		memcpy(vdp->input, ptr->data, ptr->len);
		vdp->input_len = ptr->len;
		return 0;
	}
	return -ENOENT;
}

/*
 * Update data exchanged via EVB protocol.
 * Returns true when data update succeeded.
 */
static int data_from_evb(char *ifname, struct evb22_to_vdp22 *ptr)
{
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;

	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	vdp = vdp22_findif(ifname, vud);
	if (vdp) {
		vdp->max_rwd = ptr->max_rwd;
		vdp->max_rka = ptr->max_rka;
		vdp->gpid = ptr->gpid;
		return 0;
	}
	return -ENOENT;
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
	struct vdp22_user_data *vud;
	struct vdp22 *vdp = NULL;

	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	if (vud)
		vdp = vdp22_findif(ifname, vud);
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
	int rc = -ENODEV;
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
