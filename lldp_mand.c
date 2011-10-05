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
#include <stdio.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "config.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_mand.h"
#include "lldp_mand_cmds.h"
#include "lldpad_shm.h"
#include "messages.h"
#include "lldp/l2_packet.h"
#include "lldp_tlv.h"

extern struct lldp_head lldp_head;

struct tlv_info_chassis {
	u8 sub;
	union {
		u8 ccomp[255];
		u8 ifalias[255];
		u8 pcomp[255];
		u8 mac[6];
		struct  {
			u8 type;
			union {
				struct in_addr v4;
				struct in6_addr v6;
			} __attribute__ ((__packed__)) ip;
		} __attribute__ ((__packed__)) na;
		u8 ifname[255];
		u8 local[255];
	} __attribute__ ((__packed__)) id;
} __attribute__ ((__packed__));

struct tlv_info_portid {
	u8 sub;
	union {
		u8 ifalias[255];
		u8 pcomp[255];
		u8 mac[6];
		struct  {
			u8 type;
			union {
				struct in_addr v4;
				struct in6_addr v6;
			} __attribute__ ((__packed__)) ip;
		} __attribute__ ((__packed__)) na;
		u8 ifname[255];
		u8 circuit[255];
		u8 local[255];
	} __attribute__ ((__packed__)) id;
} __attribute__ ((__packed__));

static const struct lldp_mod_ops mand_ops = {
	.lldp_mod_register 	= mand_register,
	.lldp_mod_unregister 	= mand_unregister,
	.lldp_mod_gettlv	= mand_gettlv,
	.lldp_mod_ifup		= mand_ifup,
	.lldp_mod_ifdown	= mand_ifdown,
	.client_cmd		= mand_clif_cmd,
	.get_arg_handler	= mand_get_arg_handlers,
};

static struct mand_data *mand_data(const char *ifname, enum agent_type type)
{
	struct mand_user_data *mud;
	struct mand_data *md = NULL;

	mud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_MAND);
	if (mud) {
		LIST_FOREACH(md, &mud->head, entry) {
			if (!strncmp(ifname, md->ifname, IFNAMSIZ) &&
			    (type == md->agenttype))
				return md;
		}
	}
	return NULL;
}

/*
 * mand_bld_end_tlv - build mandatory End TLV
 * @md: the mand data struct
 * 
 * Returns 0 for success or error code for failure
 *
 */
static int mand_bld_end_tlv(struct mand_data *md)
{
	int rc = EINVAL;
	struct unpacked_tlv *tlv;

	tlv = create_tlv();
	if(tlv) {
		tlv->type = END_OF_LLDPDU_TLV;
		tlv->length = 0;
		tlv->info = NULL;
		md->end = tlv;
		rc = 0;
	}
	return rc;
}

/*
 * mand_bld_chassis_tlv - build mandatory End TLV
 * @md: the mand data struct
 * 
 * Returns 0 for success or error code for failure
 *
 * Load from config if is configured, otherwise build from
 * scratc. Note that for LLDP-MED, 
 *  - Mandatory for LLDP-MED Network Connectivity w/ default to MAC
 *  - Mandatory for LLDP-MED Endpoint w/ default to network addr
 *
 * In the case of MED being enabled w/ undefined or invalid devtype?
 * we will just use network addr, assuming Endpoint device.
 * 
 * If MED is not enabled, the order, as spec says, is:
 * - CHASSIS_ID_CHASSIS_COMPONENT: only from config
 * - CHASSIS_ID_INTERFACE_ALIAS	: only from config
 * - CHASSIS_ID_PORT_COMPONENT	: only from config
 * - CHASSIS_ID_MAC_ADDRESS	: first from config, then built from scratch
 * - CHASSIS_ID_NETWORK_ADDRESS	: first from config, then built from scratch
 * - CHASSIS_ID_INTERFACE_NAME	: first from config, then built from scratch
 * - CHASSIS_ID_LOCALLY_ASSIGNED: only load from config
 *
 * TODO: 
 * - Specs says chassis should remain constant for all LLDPUs
 * while the connection remains operational, so this is built only
 * once.
 * - No validation on data loaded from config other than the subtype
 *
 */
static int mand_bld_chassis_tlv(struct mand_data *md, struct lldp_agent *agent)
{
	int rc = EINVAL;
	int devtype;
	size_t length;
	char chastr[512];
	struct unpacked_tlv *tlv;
	struct tlv_info_chassis chassis;

	/* build only once */
	if ((!md->rebuild_chassis) && (md->chassis)) {
		rc = 0;
		goto out_err;
	}

	/* free before building it */
	md->rebuild_chassis = 1;
	FREE_UNPKD_TLV(md, chassis);
	memset(&chassis, 0, sizeof(chassis));

	/* check for value in shared memory first */
	if (lldpad_shm_get_msap(md->ifname, CHASSIS_ID_TLV, (char *)&chassis, &length))
		goto bld_tlv;
	
	/* subtype may differ when LLDP-MED is enabled */
	if (!is_tlv_txenabled(md->ifname, agent->type, TLVID_MED(LLDP_MED_RESERVED)))
		goto bld_config;

	devtype = get_med_devtype(md->ifname, agent->type);
	LLDPAD_DBG("%s:%s:MED enabled w/ devtype=%d)\n",
			__func__, md->ifname, devtype);
	if (devtype == LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY)
		goto bld_macaddr;

	if ((devtype == LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I) ||
	    (devtype == LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II) ||
	    (devtype == LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III))
		goto bld_netaddr;

bld_config:
	memset(chastr, 0, sizeof(chastr));

	/* load from config */
	if (get_config_tlvinfo_str(md->ifname, agent->type, TLVID_NOUI(CHASSIS_ID_TLV),
		 		   chastr, sizeof(chastr)))
		goto bld_macaddr;
	length = strlen(chastr) / 2;
	if (hexstr2bin(chastr, (u8 *)&chassis, length))
		goto bld_macaddr;

	/* if invalid subtype, fall back to build */
	if (!CHASSIS_ID_INVALID(chassis.sub)) {
		LLDPAD_DBG("%s:%s:from config %zd bytes:str=%s\n",
			__func__, md->ifname, length, chastr);
		/* TODO: validate the loaded tlv */
		goto bld_tlv;
	}

bld_macaddr:
	/* if build from scratch, try mac, then ip, then ifname */
	get_mac(md->ifname, chassis.id.mac);
	if (is_valid_mac(chassis.id.mac)) {
		chassis.sub = CHASSIS_ID_MAC_ADDRESS;
		length = sizeof(chassis.id.mac) +
			 sizeof(chassis.sub);
		goto bld_tlv;
	}

bld_netaddr:
	/* uses ipv4 first */
	if (!get_ipaddr(md->ifname, &chassis.id.na.ip.v4)) {
		chassis.sub = CHASSIS_ID_NETWORK_ADDRESS; 
		chassis.id.na.type = MANADDR_IPV4;
		length = sizeof(chassis.id.na.type) +
			 sizeof(chassis.id.na.ip.v4) +
			 sizeof(chassis.sub);

		goto bld_tlv;
	}
	/* ipv4 fails, get ipv6 */
	if (!get_ipaddr6(md->ifname, &chassis.id.na.ip.v6)) {
		chassis.sub = CHASSIS_ID_NETWORK_ADDRESS; 
		chassis.id.na.type = MANADDR_IPV6;
		length = sizeof(chassis.id.na.type) +
			 sizeof(chassis.id.na.ip.v6) +
			 sizeof(chassis.sub);
		goto bld_tlv;
	}

	/* use ifname */
	chassis.sub = CHASSIS_ID_INTERFACE_NAME;
	strncpy((char *)chassis.id.ifname, md->ifname, IFNAMSIZ);
	length = strlen(md->ifname) + sizeof(chassis.sub);

bld_tlv:
	tlv = create_tlv();
	if (!tlv)
		goto out_err;
	tlv->type = CHASSIS_ID_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(length);
	if(!tlv->info){
		free(tlv);
		goto out_err;
	}
	memset(tlv->info, 0, tlv->length);
	memcpy(tlv->info, &chassis, tlv->length);
	md->chassis = tlv;
	md->rebuild_chassis = 0;
	/* write this back */
	lldpad_shm_set_msap(md->ifname, CHASSIS_ID_TLV, (char *)tlv->info,
			    tlv->length);

	set_config_tlvinfo_bin(md->ifname, agent->type,
			       TLVID_NOUI(CHASSIS_ID_TLV),
			       tlv->info, tlv->length);

	rc = 0;
out_err:
	return rc;
}

/*
 * mand_bld_portid_tlv - build mandatory End TLV
 * @md: the mand data struct
 * 
 * Returns 0 for success or error code for failure
 *
 * Load from config if is configured, otherwise build from
 * scratc. Note that for LLDP-MED, 
 *  - Mandatory and default to MAC for Network Connectivity, and 
 *  Endpoint Devices
 *
 * In the case of MED being enabled w/ undefined or invalid devtype?
 * we will just use mac
 * 
 * If MED is not enabled, the order, as spec says, is:
 * - PORT_ID_INTERFACE_ALIAS	: only from config
 * - PORT_ID_PORT_COMPONENT	: only from config
 * - PORT_ID_MAC_ADDRESS	: first from config, then built from scratch
 * - PORT_ID_NETWORK_ADDRESS	: first from config, then built from scratch
 * - PORT_ID_INTERFACE_NAME	: first from config, then built from scratch
 * - PORT_ID_AGENT_CIRCUIT_ID   : only from config
 * - PORT_ID_LOCALLY_ASSIGNED	: only load from config
 *
 * TODO: 
 * - The port id should remain constant for all LLDPUs while the connection
 *   remains operational, so this is built only once.
 * - No validation on data loaded from config other than the subtype
 *
 */
static int mand_bld_portid_tlv(struct mand_data *md, struct lldp_agent *agent)
{
	int rc = EINVAL;
	int devtype;
	size_t length;
	char porstr[512];
	struct unpacked_tlv *tlv;
	struct tlv_info_portid portid;


	/* build only once */
	if ((!md->rebuild_portid) && (md->portid)) {
		rc = 0;
		goto out_err;
	}

	/* free before building it */
	md->rebuild_portid = 1;
	FREE_UNPKD_TLV(md, portid);
	memset(&portid, 0, sizeof(portid));

	/* check for value in shared memory first */
	if (lldpad_shm_get_msap(md->ifname, PORT_ID_TLV, (char *)&(portid), &length))
		goto bld_tlv;

	/* subtype may differ when LLDP-MED is enabled */
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_RESERVED)))
		goto bld_config;

	devtype = get_med_devtype(md->ifname, agent->type);
	LLDPAD_DBG("%s:%s:MED enabled w/ devtype=%d)\n",
			__func__, md->ifname, devtype);

	if (LLDP_MED_DEVTYPE_DEFINED(devtype))
		goto bld_macaddr;

bld_config:
	/* load from config */

	memset(porstr, 0, sizeof(porstr));
	if (get_config_tlvinfo_str(md->ifname, agent->type,
				   TLVID_NOUI(PORT_ID_TLV),
				   porstr, sizeof(porstr)))
		goto bld_macaddr;
	length = strlen(porstr) / 2;
	if (hexstr2bin(porstr, (u8 *)&portid, length))
		goto bld_macaddr;

	/* if invalid subtype, fall back to build */
	if (!PORT_ID_INVALID(portid.sub)) {
		LLDPAD_DBG("%s:%s:from config %zd bytes:str=%s\n",
			__func__, md->ifname, length, porstr);
		/* TODO: validate the loaded tlv */
		goto bld_tlv;
	}

bld_macaddr:
	/* if build from scratch, try mac, then ip, then ifname */
	get_mac(md->ifname, portid.id.mac);
	if (is_valid_mac(portid.id.mac)) {
		portid.sub = PORT_ID_MAC_ADDRESS;
		length = sizeof(portid.id.mac) +
			 sizeof(portid.sub);
		goto bld_tlv;
	}

	/* uses ipv4 first */
	if (!get_ipaddr(md->ifname, &portid.id.na.ip.v4)) {
		portid.sub = PORT_ID_NETWORK_ADDRESS; 
		portid.id.na.type = MANADDR_IPV4;
		length = sizeof(portid.id.na.type) +
			 sizeof(portid.id.na.ip.v4) +
			 sizeof(portid.sub);

		goto bld_tlv;
	}
	/* ipv4 fails, get ipv6 */
	if (!get_ipaddr6(md->ifname, &portid.id.na.ip.v6)) {
		portid.sub = PORT_ID_NETWORK_ADDRESS; 
		portid.id.na.type = MANADDR_IPV6;
		length = sizeof(portid.id.na.type) +
			 sizeof(portid.id.na.ip.v6) +
			 sizeof(portid.sub);
		goto bld_tlv;
	}

	/* use ifname */
	portid.sub = PORT_ID_INTERFACE_NAME;
	strncpy((char *)portid.id.ifname, md->ifname, IFNAMSIZ);
	length = strlen(md->ifname) + sizeof(portid.sub);

bld_tlv:
	tlv = create_tlv();
	if (!tlv)
		goto out_err;
	tlv->type = PORT_ID_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(length);
	if(!tlv->info){
		free(tlv);
		goto out_err;
	}
	memset(tlv->info, 0, tlv->length);
	memcpy(tlv->info, &portid, tlv->length);
	md->portid = tlv;
	md->rebuild_portid = 0;
	/* write this back */
	lldpad_shm_set_msap(md->ifname, PORT_ID_TLV, (char *)tlv->info,
			    tlv->length);

	set_config_tlvinfo_bin(md->ifname, agent->type,
			       TLVID_NOUI(PORT_ID_TLV),
			       tlv->info, tlv->length);
	rc = 0;
out_err:
	return rc;
}

static int mand_bld_ttl_tlv(struct mand_data *md, struct lldp_agent *agent)
{
	int rc = EINVAL;
	u16 ttl;
	struct unpacked_tlv *tlv;

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = TIME_TO_LIVE_TLV;
	tlv->length = 2;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		goto out_err;
	}
	memset(tlv->info, 0, tlv->length);

	if (agent->tx.txTTL)
		ttl = htons(agent->tx.txTTL);
	else
		ttl = htons(DEFAULT_TX_HOLD * DEFAULT_TX_INTERVAL);

	memcpy(tlv->info, &ttl, tlv->length);
	LLDPAD_DBG("%s:%s:done:type=%d length=%d ttl=%d\n", __func__,
		md->ifname, tlv->type, tlv->length, ntohs(ttl));
	md->ttl = tlv;
	rc = 0;
out_err:
	return rc;
}

struct packed_tlv *mand_gettlv(struct port *port, struct lldp_agent *agent)
{
	struct mand_data *md;
	struct packed_tlv *ptlv = NULL;
	size_t size;

	md = mand_data(port->ifname, agent->type);
	if (!md) {
		LLDPAD_DBG("%s:%s: not found port\n", __func__, port->ifname);
		goto out_err;
	}

	size = TLVSIZE(md->chassis)
		+ TLVSIZE(md->portid)
		+ TLVSIZE(md->ttl);
	if (!size)
		goto out_err;

	ptlv = create_ptlv();
	if (!ptlv)
		goto out_err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	ptlv->size = 0;
	PACK_TLV_AFTER(md->chassis, ptlv, size, out_free);
	PACK_TLV_AFTER(md->portid, ptlv, size, out_free);
	PACK_TLV_AFTER(md->ttl, ptlv, size, out_free);
	return ptlv;
out_free:
	ptlv = free_pkd_tlv(ptlv);
out_err:
	LLDPAD_DBG("%s:%s: failed\n", __func__, port->ifname);
	return NULL;

}

static void mand_free_tlv(struct mand_data *md)
{
	if (md) {
		FREE_UNPKD_TLV(md, chassis);
		FREE_UNPKD_TLV(md, portid);
		FREE_UNPKD_TLV(md, ttl);
		FREE_UNPKD_TLV(md, end);
	}
}

/* build unpacked tlvs */
static int mand_bld_tlv(struct mand_data *md, struct lldp_agent *agent)
{
	int rc = EPERM;

	if (!port_find_by_name(md->ifname)) {
		rc = EEXIST;
		goto out_err;
	}

	if (mand_bld_chassis_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:mand_bld_chassis_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (mand_bld_portid_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:mand_bld_portid_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (mand_bld_ttl_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:mand_bld_ttl_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (mand_bld_end_tlv(md)) {
		LLDPAD_DBG("%s:%s:mand_bld_end_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	rc = 0;

out_err:
	return rc;

}

static void mand_free_data(struct mand_user_data *mud)
{
	struct mand_data *md;
	if (mud) {
		while (!LIST_EMPTY(&mud->head)) {
			md = LIST_FIRST(&mud->head);
			LIST_REMOVE(md, entry);
			mand_free_tlv(md);
			free(md);
 		}
	}
}

void mand_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct mand_data *md;

	md = mand_data(ifname, agent->type);
	if (!md)
		goto out_err;

	LIST_REMOVE(md, entry);
	mand_free_tlv(md);
	free(md);
	LLDPAD_INFO("%s:port %s removed\n", __func__, ifname); 
	return;
out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname); 
	return;
}

void mand_ifup(char *ifname, struct lldp_agent *agent)
{
	struct mand_data *md;
	struct mand_user_data *mud;

	md = mand_data(ifname, agent->type);
	if (md) {
		LLDPAD_INFO("%s:%s exists\n", __func__, ifname); 
		goto out_err;
	}
	/* not found, alloc/init per-port tlv data */
	md = (struct mand_data *) malloc(sizeof(*md));
	if (!md) {
		LLDPAD_INFO("%s:%s malloc %lu failed\n", __func__, ifname, sizeof(*md)); 
		goto out_err;
	}
	memset(md, 0, sizeof(struct mand_data));
	strncpy(md->ifname, ifname, IFNAMSIZ);
	md->agenttype = agent->type;

	if (mand_bld_tlv(md, agent)) {
		LLDPAD_INFO("%s:%s mand_bld_tlv failed\n", __func__, ifname); 
		free(md);
		goto out_err;
	}

	/* chassis is built once and remains constant */
	md->rebuild_chassis = 1; 
	/* portid is built once and remains constant */
	md->rebuild_portid = 1; 
	mud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_MAND);
	LIST_INSERT_HEAD(&mud->head, md, entry);
	LLDPAD_INFO("%s:port %s added\n", __func__, ifname); 
	return;
out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname); 
	return;
}

struct lldp_module *mand_register(void)
{
	struct lldp_module *mod;
	struct mand_user_data *mud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("failed to malloc LLDP Mandatory module data\n");
		goto out_err;
	}
	mud = malloc(sizeof(struct mand_user_data));
	if (!mud) {
		free(mod);
		LLDPAD_ERR("failed to malloc LLDP Mandatory module user data\n");
		goto out_err;
	}
	LIST_INIT(&mud->head);
 	mod->id = LLDP_MOD_MAND;
	mod->ops = &mand_ops;
	mod->data = mud;
	LLDPAD_INFO("%s:done\n", __func__);
	return mod;
out_err:
	LLDPAD_INFO("%s:failed\n", __func__);
	return NULL;
}

void mand_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		mand_free_data((struct mand_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_INFO("%s:done\n", __func__); 
}
