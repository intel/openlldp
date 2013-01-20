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

#include <stdio.h>
#include <sys/socket.h>

#include "eloop.h"
#include "lldp_ecp22.h"
#include "messages.h"
#include "lldp_ecp_utils.h"
#include "lldp/l2_packet.h"

/*
 * Find the ecp data associated with an interface.
 * Return pointer or NULL if not found.
 */
static struct ecp22 *find_ecpdata(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp = 0;

	if (eud) {
		LIST_FOREACH(ecp, &eud->head, node)
			if (!strncmp(ifname, ecp->ifname, IFNAMSIZ))
				break;
	}
	return ecp;
}

/*
 * ecp22_rx_receiveframe - receive am ecp frame
 * @ctx: rx callback context, struct ecp * in this case
 * @ifindex: index of interface
 * @buf: buffer which contains the frame just received
 * @len: size of buffer (frame)
 *
 * no return value
 *
 * creates a local copy of the buffer and checks the header. keeps some
 * statistics about ecp frames. Checks if it is a request or an ack frame and
 * branches to ecp rx or ecp tx state machine.
 */
static void ecp22_rx_receiveframe(void *ctx, int ifindex, const u8 *buf,
				  size_t len)
{
	struct ecp22 *ecp = (struct ecp22 *)ctx;

	LLDPAD_DBG("%s:%s ifindex:%d len:%zd\n", __func__, ecp->ifname, ifindex,
		   len);
	ecp_print_frame(ecp->ifname, "frame-in", buf, len);
}

/*
 * ecp22_create - create data structure and initialize ecp protocol
 * @ifname: interface for which the ecp protocol is initialized
 *
 * returns NULL on error and an pointer to the ecp22 structure on success.
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming ecp frames and initializes the ecp rx and tx state machines.
 * To be called when a successful exchange of EVB TLVs has been
 * made and ECP protocols are supported by both sides.
 */
static struct ecp22 *ecp22_create(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp;

	ecp = calloc(1, sizeof *ecp);
	if (!ecp) {
		LLDPAD_ERR("%s:%s unable to allocate ecp protocol\n", __func__,
			   ifname);
		return NULL;
	}
	strncpy(ecp->ifname, ifname, sizeof ecp->ifname);
	ecp->l2 = l2_packet_init(ecp->ifname, NULL, ETH_P_ECP22,
				 ecp22_rx_receiveframe, ecp, 1);

	if (!ecp->l2) {
		LLDPAD_ERR("%s:%s error open layer 2 ETH_P_ECP\n", __func__,
			   ifname);
		free(ecp);
		return NULL;
	}
	LIST_INSERT_HEAD(&eud->head, ecp, node);
	LLDPAD_DBG("%s:%s create ecp data\n", __func__, ifname);
	return ecp;
}

/*
 * ecp22_start - build up ecp structures for an interface
 * @ifname: name of the interface
 */
void ecp22_start(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s start ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	if (!eud) {
		LLDPAD_DBG("%s:%s no ECP module\n", __func__, ifname);
		return;
	}
	ecp = find_ecpdata(ifname, eud);
	if (!ecp)
		ecp = ecp22_create(ifname, eud);
}

static void ecp22_remove(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s remove ecp\n", __func__, ecp->ifname);
	LIST_REMOVE(ecp, node);
	free(ecp);
}

/*
 * ecp22_stop - tear down ecp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 */
void ecp22_stop(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s stop ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	ecp = find_ecpdata(ifname, eud);
	if (ecp)
		ecp22_remove(ecp);
}

static const struct lldp_mod_ops ecp22_ops =  {
	.lldp_mod_register = ecp22_register,
	.lldp_mod_unregister = ecp22_unregister
};

/*
 * ecp22_register - register ecp module to lldpad
 *
 * returns lldp_module struct on success, NULL on error
 *
 * allocates a module structure with ecp module information and returns it
 * to lldpad.
 */
struct lldp_module *ecp22_register(void)
{
	struct lldp_module *mod;
	struct ecp22_user_data *eud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s:can not allocate ecp module data\n", __func__);
		return NULL;
	}
	eud = calloc(1, sizeof(struct ecp22_user_data));
	if (!eud) {
		free(mod);
		LLDPAD_ERR("%s:can not allocate ecp user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&eud->head);
	mod->id = LLDP_MOD_ECP22;
	mod->ops = &ecp22_ops;
	mod->data = eud;
	LLDPAD_DBG("%s: done\n", __func__);
	return mod;
}

/*
 * ecp22_free_data - frees up ecp data chain
 */
static void ecp22_free_data(struct ecp22_user_data *ud)
{
	struct ecp22 *ecp;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ecp = LIST_FIRST(&ud->head);
			ecp22_remove(ecp);
		}
	}
}

/*
 * ecp22_unregister - unregister ecp module from lldpad
 *
 * no return value
 *
 * frees ecp module structure and user data.
 */
void ecp22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		ecp22_free_data((struct ecp22_user_data *)mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s: done\n", __func__);
}
