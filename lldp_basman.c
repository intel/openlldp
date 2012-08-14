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
#include <errno.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_bridge.h>
#include "lldp.h"
#include "lldp_basman.h"
#include "messages.h"
#include "clif_msgs.h"
#include "config.h"
#include "libconfig.h"
#include "lldp_mand_clif.h"
#include "lldp_basman_cmds.h"
#include "lldp_util.h"

#define SYSNAME_DEFAULT "localhost"

#define IFNUM_SUBTYPE_UNKNOWN 1
#define IFNUM_SUBTYPE_IFINDEX 2
#define IFNUM_SUBTYPE_PORTNUM 3

struct tlv_info_maddr {
	u8 len;
	u8 sub;
	union {
		struct in_addr in;
		struct in6_addr in6;
		u8 mac[6];
		u8 addr[31];
	} __attribute__ ((__packed__)) a;
} __attribute__ ((__packed__));

struct tlv_info_maif {
	u8 sub;
	u32 num;
} __attribute__ ((__packed__));

struct tlv_info_maoid {
	u8 len;
	u8 oid[128];
} __attribute__ ((__packed__));

struct tlv_info_manaddr {
	struct tlv_info_maddr m;
	struct tlv_info_maif i;
	struct tlv_info_maoid o;
} __attribute__ ((__packed__));

extern struct lldp_head lldp_head;

static const struct lldp_mod_ops basman_ops =  {
	.lldp_mod_register 	= basman_register,
	.lldp_mod_unregister 	= basman_unregister,
	.lldp_mod_gettlv	= basman_gettlv,
	.lldp_mod_ifup		= basman_ifup,
	.lldp_mod_ifdown	= basman_ifdown,
	.get_arg_handler	= basman_get_arg_handlers,
};

static struct basman_data *basman_data(const char *ifname, enum agent_type type)
{
	struct basman_user_data *bud;
	struct basman_data *bd = NULL;

	bud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_BASIC);
	if (bud) {
		LIST_FOREACH(bd, &bud->head, entry) {
			if (!strncmp(ifname, bd->ifname, IFNAMSIZ) &&
			    (type == bd->agenttype))
				return bd;
		}
	}
	return NULL;
}

/*
 * basman_bld_portdesc_tlv - build port description TLV
 * @bd: the basman data struct
 *
 * Returns 0 for success or error code for failure
 */
static int basman_bld_portdesc_tlv(struct basman_data *bd,
				   struct lldp_agent *agent)
{
	unsigned int length;
	int rc = 0;
	char desc[256];
	struct unpacked_tlv *tlv = NULL;

	/* free old if it's there */
	FREE_UNPKD_TLV(bd, portdesc);

	if (!is_tlv_txenabled(bd->ifname, agent->type, PORT_DESCRIPTION_TLV)) {
		LLDPAD_DBG("%s:%s:Port Description disabled\n",
			__func__, bd->ifname);
		goto out_err;
	}

	/* load from config */
	if (!get_config_tlvinfo_str(bd->ifname, agent->type,
				    TLVID_NOUI(PORT_DESCRIPTION_TLV),
				    desc, sizeof(desc))) {
		/* use what's in the config */
		length = strlen(desc);
		LLDPAD_DBG("%s:%s:configed as %s\n", __func__, bd->ifname, desc);
	} else {
		length = snprintf(desc, sizeof(desc), "Interface %3d as %s",
		 	  if_nametoindex(bd->ifname), bd->ifname);
		LLDPAD_DBG("%s:%s:built as %s\n", __func__, bd->ifname, desc);
	}
	if (length >= sizeof(desc))
		length = sizeof(desc) - 1;

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = PORT_DESCRIPTION_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, desc, tlv->length);
	bd->portdesc = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * basman_bld_sysname_tlv - build port description TLV
 * @bd: the basman data struct
 *
 * Returns 0 for success or error code for failure
 */
static int basman_bld_sysname_tlv(struct basman_data *bd,
				  struct lldp_agent *agent)
{
	unsigned int length;
	int rc = 0;
	char desc[256];
	struct utsname uts;
	struct unpacked_tlv *tlv = NULL;

	/* free old if it's there */
	FREE_UNPKD_TLV(bd, sysname);

	if (!is_tlv_txenabled(bd->ifname, agent->type, SYSTEM_NAME_TLV)) {
		LLDPAD_DBG("%s:%s:System Name disabled\n",
			__func__, bd->ifname);
		goto out_err;
	}

	/* load from config */
	if (!get_config_tlvinfo_str(bd->ifname, agent->type,
				    TLVID_NOUI(SYSTEM_NAME_TLV),
				    desc, sizeof(desc))) {
		/* use what's in the config */
		LLDPAD_DBG("%s:%s:configed as %s\n",
			__func__, bd->ifname, desc);
	} else {
		const char *node_name;

		if (uname(&uts))
			node_name = SYSNAME_DEFAULT;
		else
			node_name = uts.nodename;
		strncpy(desc, node_name, sizeof(desc));
		desc[sizeof(desc) - 1] = 0;
		LLDPAD_DBG("%s:%s:built as %s\n", __func__, bd->ifname, desc);
	}
	length = strlen(desc);
	if (length >= sizeof(desc))
		length = sizeof(desc) - 1;

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = SYSTEM_NAME_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info){
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, desc, tlv->length);
	bd->sysname = tlv;
	rc = 0;
out_err:
	return rc;
}


/*
 * basman_bld_sysdesc_tlv - build port description TLV
 * @bd: the basman data struct
 *
 * Returns 0 for success or error code for failure
 *
 * net-snmp-utils: snmptest returns the following for sysDesr: `uname-a`
 */
static int basman_bld_sysdesc_tlv(struct basman_data *bd,
				  struct lldp_agent *agent)
{
	unsigned int length;
	int rc = 0;
	char desc[256];
	struct utsname uts;
	struct unpacked_tlv *tlv = NULL;

	/* free old if it's there */
	FREE_UNPKD_TLV(bd, sysdesc);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      SYSTEM_DESCRIPTION_TLV)) {
		LLDPAD_DBG("%s:%s:System Description disabled\n",
			__func__, bd->ifname);
		goto out_err;
	}

	/* load from config */
	if (!get_config_tlvinfo_str(bd->ifname, agent->type,
				    TLVID_NOUI(SYSTEM_DESCRIPTION_TLV),
				    desc, sizeof(desc))) {
		/* use what's in the config */
		length = strlen(desc);
		LLDPAD_DBG("%s:%s:configed as %s\n",
			__func__, bd->ifname, desc);
	} else {
		if (uname(&uts)) {
			length = snprintf(desc, sizeof(desc), "Unknown system");
		} else {
			length = snprintf(desc, sizeof(desc), "%s %s %s %s %s",
					  uts.sysname, uts.nodename, uts.release,
					  uts.version, uts.machine);
		}
		LLDPAD_DBG("%s:%s:built as %s\n",
			__func__, bd->ifname, desc);
	}
	if (length >= sizeof(desc))
		length = sizeof(desc) - 1;

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = SYSTEM_DESCRIPTION_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info){
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, desc, tlv->length);
	bd->sysdesc = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * basman_bld_syscaps_tlv - build port description TLV
 * @bd: the basman data struct
 *
 * Returns 0 for success or error code for failure
 *
 * TODO:
 *  - This is mandatory for LLDP-MED Class III
 *  - TPID to determine C-VLAN vs. S-VLAN ?
 */
static int basman_bld_syscaps_tlv(struct basman_data *bd,
				  struct lldp_agent *agent)
{
	int rc = 0;
	u16 syscaps[2];
	struct unpacked_tlv *tlv = NULL;

	/* free old if it's there */
	FREE_UNPKD_TLV(bd, syscaps);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      SYSTEM_CAPABILITIES_TLV)) {
		LLDPAD_DBG("%s:%s:System Capabilities disabled\n",
			__func__, bd->ifname);
		goto out_err;
	}

	/* load from config */
	if (get_config_tlvinfo_bin(bd->ifname, agent->type,
				   TLVID_NOUI(SYSTEM_CAPABILITIES_TLV),
				   &syscaps, sizeof(syscaps))) {
		LLDPAD_DBG("%s:%s:Build System Caps from scratch\n",
			__func__, bd->ifname);
		syscaps[0] = htons(get_caps(bd->ifname));
		syscaps[1] = (is_active(bd->ifname)) ? syscaps[0] : 0;
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = SYSTEM_CAPABILITIES_TLV;
	tlv->length = sizeof(syscaps);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, &syscaps, tlv->length);
	bd->syscaps = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * basman_get_manaddr_sub - build management address TLV by subtype
 * @bd: the basman data struct
 * @masub: IETF RFC 3232 ianaAddressFamilyNumbers
 *
 * Returns 0 for success or error code for failure
 *
 * Currently supports only IPv4, IPv6, and MAC address types.
 *
 */
static int basman_get_manaddr_sub(struct basman_data *bd,
				  struct lldp_agent *agent, u8 masub)
{
	int domain;
	int length = 0;
	int rc = EINVAL;
	u8 *data = NULL;
	char maddr[128];
	char *field = NULL;
	struct tlv_info_maif *i = NULL;
	struct tlv_info_maddr *m = NULL;
	struct tlv_info_maoid *o = NULL;
	struct tlv_info_manaddr manaddr;
	struct unpacked_tlv *tlv = NULL;

	if (bd->macnt >= MANADDR_MAX) {
		LLDPAD_DBG("%s:%s:reached max %d Management Address\n",
			__func__, bd->ifname, bd->macnt);
		goto out_err;
	}

	memset(maddr, 0, sizeof(maddr));
	memset(&manaddr, 0, sizeof(manaddr));
	m = &manaddr.m;
	m->sub = masub;
	switch(m->sub) {
	case MANADDR_IPV4:
		field = "ipv4";
		domain = AF_INET;
		m->len = sizeof(m->a.in);
		break;
	case MANADDR_IPV6:
		field = "ipv6";
		domain = AF_INET6;
		m->len = sizeof(m->a.in6);
		break;
	case MANADDR_ALL802:
		field = "mac";
		domain = AF_UNSPEC;
		m->len = sizeof(m->a.mac);
		break;
	default:
		LLDPAD_DBG("%s:%s:unsupported sub type %d\n",
			__func__, bd->ifname, masub);
		goto out_err;
	}
	m->len += sizeof(m->sub);

	/* read from the config first */
	if (get_config_tlvfield_str(bd->ifname,
				    agent->type,
				    TLVID_NOUI(MANAGEMENT_ADDRESS_TLV),
				    field, maddr, sizeof(maddr))) {
		LLDPAD_DBG("%s:%s:failed to get %s from config\n",
			__func__, bd->ifname, field);
		goto out_bld;
	}
	if (!str2addr(domain, maddr, &m->a, sizeof(m->a))) {
		goto out_set;
	}

out_bld:
	/* failed to get from config, so build from scratch */
	if (get_addr(bd->ifname, domain, &m->a)) {
		LLDPAD_DBG("%s:%s:get_addr() for domain %d failed\n",
			__func__, bd->ifname, domain);
		goto out_err;
	}
	if (addr2str(domain, &m->a, maddr, sizeof(maddr))) {
		LLDPAD_DBG("%s:%s:get_addr() for domain %d failed\n",
			__func__, bd->ifname, domain);
		goto out_err;
	}

out_set:
	set_config_tlvfield_str(bd->ifname,
				agent->type,
				TLVID_NOUI(MANAGEMENT_ADDRESS_TLV),
				field, maddr);

	/* build ifnum and oid:
	 *  mlen + msub + maddr  + ifsub + ifidx + oidlen + oid
	 *  1    + 1    + [1-31] + 1     + 4     + 1       + [1-128]
	 */
	data = (u8 *)&manaddr;
	length = sizeof(manaddr.m.len) + manaddr.m.len;
	i = (struct tlv_info_maif *)&data[length];
	i->sub = IFNUM_SUBTYPE_IFINDEX;
	i->num = htonl(if_nametoindex(bd->ifname));

	length += sizeof(struct tlv_info_maif);
	o = (struct tlv_info_maoid *)&data[length];
	o->len = 0;
	length += sizeof(o->len) + o->len;

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->length = length;
	tlv->type = MANAGEMENT_ADDRESS_TLV;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}

	memcpy(tlv->info, &manaddr, tlv->length);
	bd->manaddr[bd->macnt] = tlv;
	bd->macnt++;

	LLDPAD_DBG("%s:%s:maddr[%d]:tlv->len %d bytes \n",
		__func__, bd->ifname, bd->macnt, tlv->length);

	rc = 0;
out_err:
	return rc;
}

/*
 * basman_bld_manddrr_tlv - build management address TLV
 * @bd: the basman data struct
 *
 * Returns 0 for success or error code for failure
 *
 * Use as many existing as possible
 * Preference is config > ipv6 > ipv4 > mac > default
 *
 * Max info length is = 1 + 1 + 31 + 1 + 4 + 1 + 128 = 167
 *
 * TODO:
 *  - No support for OID yet
 */
static int basman_bld_manaddr_tlv(struct basman_data *bd,
				  struct lldp_agent *agent)
{
	int i;
	int rc = 0;

	/* free all existing manaddr TLVs */
	for (i = 0; i < bd->macnt; i++)
		FREE_UNPKD_TLV(bd, manaddr[i]);
	bd->macnt = 0;

	/* ignore manaddr if it's not enabled for tx */
	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      MANAGEMENT_ADDRESS_TLV)) {
		LLDPAD_DBG("%s:%s:Management Address disabled\n",
			__func__, bd->ifname);
		goto out_err;
	}

	/* management addr preference: ipv4, ipv6, mac */
	rc = basman_get_manaddr_sub(bd, agent, MANADDR_IPV4);
	if (rc) {
		rc = basman_get_manaddr_sub(bd, agent, MANADDR_IPV6);
		if (rc)
			basman_get_manaddr_sub(bd, agent, MANADDR_ALL802);
	}
out_err:
	return rc;
}

static void basman_free_tlv(struct basman_data *bd)
{
	int i = 0;

	if (bd) {
		FREE_UNPKD_TLV(bd, portdesc);
		FREE_UNPKD_TLV(bd, sysname);
		FREE_UNPKD_TLV(bd, sysdesc);
		FREE_UNPKD_TLV(bd, syscaps);
		for (i = 0; i < bd->macnt; i++)
			FREE_UNPKD_TLV(bd, manaddr[i]);
		bd->macnt = 0;
	}
}

/* build unpacked tlvs */
static int basman_bld_tlv(struct basman_data *bd, struct lldp_agent *agent)
{
	int rc = EPERM;

	if (!port_find_by_name(bd->ifname)) {
		rc = EEXIST;
		goto out_err;
	}

	if (basman_bld_portdesc_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:basman_bld_portdesc_tlv() failed\n",
				__func__, bd->ifname);
		goto out_err;
	}
	if (basman_bld_sysname_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:basman_bld_sysname_tlv() failed\n",
				__func__, bd->ifname);
		goto out_err;
	}
	if (basman_bld_sysdesc_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:basman_bld_sysdesc_tlv() failed\n",
				__func__, bd->ifname);
		goto out_err;
	}
	if (basman_bld_syscaps_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:basman_bld_syscaps_tlv() failed\n",
				__func__, bd->ifname);
		goto out_err;
	}
	if (basman_bld_manaddr_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:basman_bld_manaddr_tlv() failed\n",
				__func__, bd->ifname);
		goto out_err;
	}
	rc = 0;

out_err:
	return rc;
}

static void basman_free_data(struct basman_user_data *bud)
{
	struct basman_data *bd;
	if (bud) {
		while (!LIST_EMPTY(&bud->head)) {
			bd = LIST_FIRST(&bud->head);
			LIST_REMOVE(bd, entry);
			basman_free_tlv(bd);
			free(bd);
 		}
	}
}

struct packed_tlv *basman_gettlv(struct port *port, struct lldp_agent *agent)
{
	int i;
	int size;
	struct basman_data *bd;
	struct packed_tlv *ptlv = NULL;

	bd = basman_data(port->ifname, agent->type);
	if (!bd)
		goto out_err;

	/* free and rebuild the TLVs */
	basman_free_tlv(bd);
	if (basman_bld_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s basman_bld_tlv failed\n",
			__func__, port->ifname);
		goto out_err;
	}

	size = TLVSIZE(bd->portdesc)
		+ TLVSIZE(bd->sysname)
		+ TLVSIZE(bd->sysdesc)
		+ TLVSIZE(bd->syscaps);

	for (i = 0; i < bd->macnt; i++)
		size += TLVSIZE(bd->manaddr[i]);

	if (!size)
		goto out_err;

	ptlv = create_ptlv();
	if (!ptlv) {
		LLDPAD_DBG("%s:%s malloc(ptlv) failed\n",
			   __func__, port->ifname);
		goto out_err;
	}

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	/* pack all pre-built tlvs */
	ptlv->size = 0;
	PACK_TLV_AFTER(bd->portdesc, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->sysname, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->sysdesc, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->syscaps, ptlv, size, out_free);
	for (i = 0; i < bd->macnt; i++)
		PACK_TLV_AFTER(bd->manaddr[i], ptlv, size, out_free);
	return ptlv;
out_free:
	ptlv = free_pkd_tlv(ptlv);
out_err:
	LLDPAD_DBG("%s:%s: failed\n", __func__, port->ifname);
	return NULL;
}

void basman_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct basman_data *bd;

	bd = basman_data(ifname, agent->type);
	if (!bd)
		goto out_err;

	LIST_REMOVE(bd, entry);
	basman_free_tlv(bd);
	free(bd);
	LLDPAD_DBG("%s:port %s removed\n", __func__, ifname);
	return;
out_err:
	LLDPAD_DBG("%s:port %s adding failed\n", __func__, ifname);
	return;
}

void basman_ifup(char *ifname, struct lldp_agent *agent)
{
	struct basman_data *bd;
	struct basman_user_data *bud;

	bd = basman_data(ifname, agent->type);
	if (bd) {
		LLDPAD_DBG("%s:%s exists\n", __func__, ifname);
		goto out_err;
	}

	/* not found, alloc/init per-port tlv data */
	bd = (struct basman_data *) malloc(sizeof(*bd));
	if (!bd) {
		LLDPAD_DBG("%s:%s malloc %zu failed\n",
			 __func__, ifname, sizeof(*bd));
		goto out_err;
	}
	memset(bd, 0, sizeof(struct basman_data));
	strncpy(bd->ifname, ifname, IFNAMSIZ);
	bd->agenttype = agent->type;

	if (basman_bld_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s mand_bld_tlv failed\n", __func__, ifname);
		free(bd);
		goto out_err;
	}

	bud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_BASIC);
	LIST_INSERT_HEAD(&bud->head, bd, entry);
	LLDPAD_DBG("%s:port %s added\n", __func__, ifname);
	return;
out_err:
	LLDPAD_DBG("%s:port %s adding failed\n", __func__, ifname);
	return;
}

struct lldp_module *basman_register(void)
{
	struct lldp_module *mod;
	struct basman_user_data *bud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("failed to malloc LLDP Basic Management module data\n");
		goto out_err;
	}
	bud = malloc(sizeof(struct basman_user_data));
	if (!bud) {
		free(mod);
		LLDPAD_ERR("failed to malloc LLDP Basic Management module user data\n");
		goto out_err;
	}
	LIST_INIT(&bud->head);
 	mod->id = LLDP_MOD_BASIC;
	mod->ops = &basman_ops;
	mod->data = bud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;
out_err:
	LLDPAD_DBG("%s:failed\n", __func__);
	return NULL;
}

void basman_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		basman_free_data((struct basman_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done\n", __func__);
}
