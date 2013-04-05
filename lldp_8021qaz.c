/******************************************************************************

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

******************************************************************************/

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include "lldp.h"
#include "lldp_8021qaz.h"
#include "messages.h"
#include "lldp_util.h"
#include "dcb_driver_interface.h"
#include "config.h"
#include "lldp_mand_clif.h"
#include "lldp_dcbx_nl.h"
#include "lldp/l2_packet.h"
#include "lldp/ports.h"
#include "lldpad_status.h"
#include "lldp_8021qaz_cmds.h"
#include "lldp_mand_clif.h"
#include "include/linux/dcbnl.h"
#include "include/linux/rtnetlink.h"
#include "include/linux/netlink.h"
#include "lldp_dcbx.h"


struct lldp_head lldp_head;
struct config_t lldpad_cfg;

static int ieee8021qaz_check_pending(struct port *port, struct lldp_agent *);
static void run_all_sm(struct port *port, struct lldp_agent *agent);
static void ieee8021qaz_mibUpdateObjects(struct port *port);
static void ieee8021qaz_app_reset(struct app_tlv_head *head);
static int get_ieee_hw(const char *ifname, struct ieee_ets **ets,
		       struct ieee_pfc **pfc, struct app_prio **app,
		       int *cnt);

static const struct lldp_mod_ops ieee8021qaz_ops = {
	.lldp_mod_register	= ieee8021qaz_register,
	.lldp_mod_unregister	= ieee8021qaz_unregister,
	.lldp_mod_gettlv	= ieee8021qaz_gettlv,
	.lldp_mod_rchange	= ieee8021qaz_rchange,
	.lldp_mod_ifup		= ieee8021qaz_ifup,
	.lldp_mod_ifdown	= ieee8021qaz_ifdown,
	.lldp_mod_mibdelete	= ieee8021qaz_mibDeleteObject,
	.get_arg_handler	= ieee8021qaz_get_arg_handlers,
	.timer			= ieee8021qaz_check_pending,
};

static int ieee8021qaz_check_pending(struct port *port,
				     struct lldp_agent *agent)
{
	struct ieee8021qaz_user_data *iud;
	struct ieee8021qaz_tlvs *tlv = NULL;

	if (agent->type != NEAREST_BRIDGE)
		return 0;

	if (!port->portEnabled)
		return 0;

	iud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_8021QAZ);
	if (iud) {
		LIST_FOREACH(tlv, &iud->head, entry) {
			if (!strncmp(port->ifname, tlv->ifname, IFNAMSIZ)) {
				if (tlv->active && tlv->pending &&
				    port->dormantDelay == 1) {
					tlv->pending = false;
					ieee8021qaz_app_reset(&tlv->app_head);
					run_all_sm(port, agent);
					somethingChangedLocal(port->ifname,
							      agent->type);
				}
				break;
			}
		}
	}

	return 0;
}

/* LLDP_8021QAZ_MOD_OPS - REGISTER */
struct lldp_module *ieee8021qaz_register(void)
{
	struct lldp_module *mod;
	struct ieee8021qaz_user_data *iud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("Failed to malloc LLDP-8021QAZ module data");
		goto out_err;
	}

	iud = malloc(sizeof(*iud));
	if (!iud) {
		free(mod);
		LLDPAD_ERR("Failed to malloc LLDP-8021QAZ module user data");
		goto out_err;
	}
	memset((void *) iud, 0, sizeof(struct ieee8021qaz_user_data));

	LIST_INIT(&iud->head);

	mod->id	  = LLDP_MOD_8021QAZ;
	mod->ops  = &ieee8021qaz_ops;
	mod->data = iud;

	LLDPAD_DBG("%s: ieee8021qaz_register SUCCESS\n", __func__);
	return mod;

out_err:
	LLDPAD_DBG("%s: ieee8021qaz_register FAILED\n", __func__);
	return NULL;
}

struct ieee8021qaz_tlvs *ieee8021qaz_data(const char *ifname)
{
	struct ieee8021qaz_user_data *iud;
	struct ieee8021qaz_tlvs *tlv = NULL;

	iud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_8021QAZ);
	if (iud) {
		LIST_FOREACH(tlv, &iud->head, entry) {
			if (!strncmp(tlv->ifname, ifname, IFNAMSIZ))
				return tlv;
		}
	}

	return NULL;
}

static void set_ets_prio_map(const char *arg, u32 *prio_map)
{
		char *argcpy = strdup(arg);
		char *tokens;
		int tc, prio;

		if (!argcpy)
			return;

		tokens = strtok(argcpy, ",");

		while (tokens) {
			prio = 0x7 & atoi(tokens);
			tc = 0x7 & atoi(&tokens[2]);
			*prio_map |= tc << (4 * (7-prio));
			tokens = strtok(NULL, ",");
		}
		free(argcpy);
}

static void set_ets_tsa_map(const char *arg, u8 *tsa_map)
{
	int i, type, tc;
	char *argcpy = strdup(arg);
	char *tokens;

	if (!argcpy)
		return;

	tokens = strtok(argcpy, ",");

	for (i = 0; tokens; i++) {
		tc = atoi(tokens);
		if ((strcmp(&tokens[2], "strict")) == 0)
			type = IEEE8021Q_TSA_STRICT;
		else if ((strcmp(&tokens[2], "cb_shaper")) == 0)
			type = IEEE8021Q_TSA_CBSHAPER;
		else if ((strcmp(&tokens[2], "ets")) == 0)
			type = IEEE8021Q_TSA_ETS;
		else if ((strcmp(&tokens[2], "vendor")) == 0)
			type = IEEE8021Q_TSA_VENDOR;
		else
			type = IEEE8021Q_TSA_STRICT;

		tsa_map[tc] = type;
		tokens = strtok(NULL, ",");
	}
	free(argcpy);
}

static int read_cfg_file(char *ifname, struct lldp_agent *agent,
			 struct ieee8021qaz_tlvs *tlvs)
{
	const char *arg = NULL;
	char arg_path[256];
	int res = 0, i;
	int willing, pfc_mask, delay;

	if (agent->type != NEAREST_BRIDGE)
		return 0;

	/* Read ETS-CFG willing bit -- default willing enabled */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSCFG), ARG_WILLING);
	res = get_config_setting(ifname, agent->type, arg_path, &willing,
				 CONFIG_TYPE_INT);
	if (!res)
		tlvs->ets->cfgl->willing = !!willing;
	else
		tlvs->ets->cfgl->willing = 1;

	/* Read PFC willing bit -- default willing enabled */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_PFC), ARG_WILLING);
	res = get_config_setting(ifname, agent->type, arg_path, &willing,
				 CONFIG_TYPE_INT);
	if (!res)
		tlvs->pfc->local.willing = !!willing;
	else
		tlvs->pfc->local.willing = 1;

	/* Read and parse ETS-CFG priority map --
	 * default all priorities TC0
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSCFG), ARG_ETS_UP2TC);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res)
		set_ets_prio_map(arg, &tlvs->ets->cfgl->prio_map);
	else
		tlvs->ets->cfgl->prio_map = 0x00000000;

	/* Default ETS-CFG num_tc to MAX */
	tlvs->ets->cfgl->max_tcs = MAX_TCS;

	/* Read and parse ETS-REC priority map --
	 * default all priorities TC0
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSREC), ARG_ETS_UP2TC);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res)
		set_ets_prio_map(arg, &tlvs->ets->recl->prio_map);
	else
		tlvs->ets->recl->prio_map = 0x00000000;

	/* Read and parse ETS-CFG tc bandwidth map --
	 * default percentage mapping 0,0,0,0,0,0,0,0 (strict priority)
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSCFG), ARG_ETS_TCBW);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res) {
		char *argcpy = strdup(arg);
		char *tokens;

		if (argcpy) {
			tokens = strtok(argcpy, ",");

			for (i = 0; tokens; i++) {
				tlvs->ets->cfgl->tc_bw[i] = atoi(tokens);
				tokens = strtok(NULL, ",");
			}
			free(argcpy);
		}
	}

	/* Read and parse ETS-REC tc bandwidth map --
	 * default percentage mapping 0,0,0,0,0,0,0,0 (strict priority)
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSREC), ARG_ETS_TCBW);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res) {
		char *argcpy = strdup(arg);
		char *tokens;

		if (argcpy) {
			tokens = strtok(argcpy, ",");

			for (i = 0; tokens; i++) {
				tlvs->ets->recl->tc_bw[i] = atoi(tokens);
				tokens = strtok(NULL, ",");
			}
			free(argcpy);
		}
	}

	/* Read and parse ETS-CFG tc transmission selction algorithm map
	 * This defaults to all traffic classes using strict priority
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSCFG), ARG_ETS_TSA);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res) {
		set_ets_tsa_map(arg, tlvs->ets->cfgl->tsa_map);
	} else {
		for (i = 0; i < MAX_TCS; i++)
			tlvs->ets->cfgl->tsa_map[i] = IEEE8021Q_TSA_STRICT;
	}

	/* Read and parse ETS-REC tc transmission selction algorithm map
	 * This defaults to all traffic classes using strict priority
	 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_ETSREC), ARG_ETS_TSA);
	res = get_config_setting(ifname, agent->type, arg_path, &arg,
				 CONFIG_TYPE_STRING);
	if (!res) {
		set_ets_tsa_map(arg, tlvs->ets->recl->tsa_map);
	} else {
		for (i = 0; i < MAX_TCS; i++)
			tlvs->ets->recl->tsa_map[i] = IEEE8021Q_TSA_STRICT;
	}

	/* Read and parse PFC enable bitmask -- default 0x00 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_PFC), ARG_PFC_ENABLED);
	res = get_config_setting(ifname, agent->type, arg_path, &pfc_mask,
				 CONFIG_TYPE_INT);
	if (!res)
		tlvs->pfc->local.pfc_enable = pfc_mask;

	/* Read and parse PFC delay -- default 0x00 */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8021(LLDP_8021QAZ_PFC), ARG_PFC_DELAY);
	res = get_config_setting(ifname, agent->type, arg_path, &delay,
				 CONFIG_TYPE_INT);
	if (!res)
		tlvs->pfc->local.delay = delay;

	/* Default PFC capabilities to MAX */
	tlvs->pfc->local.pfc_cap = MAX_TCS;

	/* Read and add APP data to internal lldpad APP ring */
	for (i = 0; i < MAX_APP_ENTRIES; i++) {
		char *parse;
		char *app_tuple;
		u8 prio, sel;
		long pid;

		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s%i", TLVID_PREFIX,
			 TLVID_8021(LLDP_8021QAZ_APP), ARG_APP, i);
		res = get_config_setting(ifname, agent->type, arg_path, &arg,
					 CONFIG_TYPE_STRING);

		if (res)
			continue;

		/* Parse cfg file input, bounds checking done on set app cmd */
		parse = strdup(arg);
		if (!parse)
			break;
		app_tuple = strtok(parse, ",");
		if (!app_tuple)
			break;
		prio = atoi(app_tuple);
		app_tuple = strtok(NULL, ",");
		if (!app_tuple)
			break;
		sel = atoi(app_tuple);

		app_tuple = strtok(NULL, ",");
		if (!app_tuple)
			break;

		/* APP Data can be in hex or integer form */
		errno = 0;
		pid = strtol(app_tuple, NULL, 0);
		if (!errno)
			ieee8021qaz_mod_app(&tlvs->app_head, 0,
					    prio, sel, (u16) pid, 0);
		free(parse);
	}

	return 0;
}

inline int get_prio_map(u32 prio_map, int prio)
{
	if (prio > 7)
		return 0;

	return (prio_map >> (4 * (7-prio))) & 0xF;
}

inline void set_prio_map(u32 *prio_map, u8 prio, int tc)
{
	u32 mask = ~(0xffffffff & (0xF << (4 * (7-prio))));
	*prio_map &= mask;
	*prio_map |= tc << (4 * (7-prio));
}

/*
 * get_dcbx_hw - Get bitmask of hardware DCBX version and firmware status
 *
 * @ifname: interface name to query
 * @dcbx: bitmask to store DCBX capabilities
 *
 * Returns 0 on success, error value otherwise.
 */
static int get_dcbx_hw(const char *ifname, __u8 *dcbx)
{
	int err = 0;
	struct nlattr *attr;
	struct sockaddr_nl dest_addr;
	static struct nl_handle *nlhandle;
	struct nl_msg *nlm = NULL;
	unsigned char *msg = NULL;
	struct nlmsghdr *hdr;
	struct dcbmsg d = {
			   .dcb_family = AF_UNSPEC,
			   .cmd = DCB_CMD_GDCBX,
			   .dcb_pad = 0
			  };

	if (!nlhandle) {
		nlhandle = nl_handle_alloc();
		if (!nlhandle) {
			LLDPAD_WARN("%s: %s: nl_handle_alloc failed, %s\n",
				    __func__, ifname, nl_geterror());
			err = -ENOMEM;
			goto out;
		}
		nl_socket_set_local_port(nlhandle, 0);
	}

	err = nl_connect(nlhandle, NETLINK_ROUTE);
	if (err < 0) {
		LLDPAD_WARN("%s: %s nlconnect failed abort get ieee, %s\n",
			    __func__, ifname, nl_geterror());
		goto out;
	}

	nlm = nlmsg_alloc_simple(RTM_GETDCB, NLM_F_REQUEST);
	if (!nlm) {
		LLDPAD_WARN("%s: %s nlmsg_alloc failed abort get ieee, %s\n",
			    __func__, ifname, nl_geterror());
		err = -ENOMEM;
		goto out;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	nlmsg_set_dst(nlm, &dest_addr);

	err = nlmsg_append(nlm, &d, sizeof(d), NLMSG_ALIGNTO);
	if (err < 0)
		goto out;

	err = nla_put(nlm, DCB_ATTR_IFNAME, strlen(ifname)+1, ifname);
	if (err < 0)
		goto out;

	err = nl_send_auto_complete(nlhandle, nlm);
	if (err <= 0) {
		LLDPAD_WARN("%s: %s 802.1Qaz get app attributes failed\n",
			    __func__, ifname);
		goto out;
	}

	err = nl_recv(nlhandle, &dest_addr, &msg, NULL);
	if (err <= 0) {
		LLDPAD_WARN("%s: %s: nl_recv returned %d\n", __func__, ifname,
			    err);
		goto out;
	}

	hdr = (struct nlmsghdr *) msg;

	attr = nlmsg_find_attr(hdr, sizeof(d), DCB_ATTR_DCBX);
	if (!attr) {
		LLDPAD_DBG("%s: %s: nlmsg_find_attr failed, no GDCBX support\n",
			    __func__, ifname);
		goto out;
	}

	*dcbx = nla_get_u8(attr);
out:
	nlmsg_free(nlm);
	free(msg);
	if (nlhandle)
		nl_close(nlhandle);
	return err;
}

/*
 * LLDP_8021QAZ_MOD_OPS - IFUP
 *
 * Load TLV values (either from config file, command prompt or defaults),
 * set up adapter, initialize FSMs and build tlvs
 *
 * Check if a 'config' file exists (to load tlv values). If YES, load save them
 * as new defaults. If NO, load defaults. Also, check for TLV values via cmd
 * prompt. Then initialize FSMs for each tlv and finally build the tlvs
 */
void ieee8021qaz_ifup(char *ifname, struct lldp_agent *agent)
{
	struct port *port = NULL;
	struct ieee8021qaz_tlvs *tlvs;
	struct ieee8021qaz_user_data *iud;
	int adminstatus, cnt, len;
	__u8 dcbx = 0;
	struct ieee_ets *ets = NULL;
	struct ieee_pfc *pfc = NULL;
	struct app_prio *data = NULL;
	int err;

	if (agent->type != NEAREST_BRIDGE)
		return;

	/* 802.1Qaz does not support bonded or vlan devices */
	if (is_bond(ifname) || is_vlan(ifname))
		return;

	err = get_dcbx_hw(ifname, &dcbx);
	if (err < 0)
		return;

	/* If hardware is not DCBX IEEE compliant or it is managed
	 * by an LLD agent most likely a firmware agent abort
	 */
	if (!(dcbx & DCB_CAP_DCBX_VER_IEEE) ||
	    (dcbx & DCB_CAP_DCBX_LLD_MANAGED))
		return;

	/* If 802.1Qaz is already configured no need to continue */
	tlvs = ieee8021qaz_data(ifname);
	if (tlvs)
		goto initialized;

	/* if there is no persistent adminStatus setting then set to enabledRx
	 * but do not persist that as a setting.
	 */
	if (get_config_setting(ifname, agent->type, ARG_ADMINSTATUS,
			       &adminstatus, CONFIG_TYPE_INT))
		set_lldp_agent_admin(ifname, agent->type, enabledRxOnly);

	/* lookup port data */
	port = porthead;
	while (port != NULL) {
		if (!strncmp(ifname, port->ifname, MAX_DEVICE_NAME_LEN))
			break;
		port = port->next;
	}

	/*
	 * Check if link down and/or tlvs exist for current port.
	 * If true, then return without any further work
	 */
	if (!port)
		return;

	/* Initializing TLV structs */
	tlvs = malloc(sizeof(*tlvs));
	if (!tlvs) {
		LLDPAD_DBG("%s: ifname %s malloc failed.\n", __func__, ifname);
		return;
	}
	memset(tlvs, 0, sizeof(*tlvs));

	tlvs->rx = malloc(sizeof(*tlvs->rx));
	if (!tlvs->rx) {
		free(tlvs);
		LLDPAD_DBG("%s: %s malloc failed.\n", __func__, ifname);
		return;
	}
	memset(tlvs->rx, 0, sizeof(*tlvs->rx));

	/* Initializing the ieee8021qaz_tlvs struct */
	strncpy(tlvs->ifname, ifname, IFNAMSIZ);
	tlvs->port = port;
	tlvs->ieee8021qazdu = 0;
	l2_packet_get_own_src_addr(port->l2, tlvs->local_mac);
	memset(tlvs->remote_mac, 0, ETH_ALEN);

	/* Initialize all TLVs */
	tlvs->ets = malloc(sizeof(*tlvs->ets));
	if (!tlvs->ets)
		goto err;
	memset(tlvs->ets, 0, sizeof(*tlvs->ets));

	tlvs->ets->cfgl = malloc(sizeof(*tlvs->ets->cfgl));
	if (!tlvs->ets->cfgl)
		goto err;

	tlvs->ets->recl = malloc(sizeof(*tlvs->ets->recl));
	if (!tlvs->ets->recl)
		goto err_recl;

	tlvs->pfc = malloc(sizeof(*tlvs->pfc));
	if (!tlvs->pfc)
		goto err_pfc;

	memset(tlvs->ets->cfgl, 0, sizeof(*tlvs->ets->cfgl));
	memset(tlvs->ets->recl, 0, sizeof(*tlvs->ets->recl));
	memset(tlvs->pfc, 0, sizeof(*tlvs->pfc));

	tlvs->ets->pending = 1;
	tlvs->ets->current_state = 0;

	tlvs->pfc->pending = 1;
	tlvs->pfc->current_state = 0;
	tlvs->pfc->remote_param = 0;

	LIST_INIT(&tlvs->app_head);
	read_cfg_file(port->ifname, agent, tlvs);

	iud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_8021QAZ);
	LIST_INSERT_HEAD(&iud->head, tlvs, entry);

initialized:
	/* Query hardware and set maximum number of TCs with hardware values */
	len = get_ieee_hw(ifname, &ets, &pfc, &data, &cnt);
	if (len > 0) {
		tlvs->ets->cfgl->max_tcs = ets->ets_cap;
		tlvs->pfc->local.pfc_cap = pfc->pfc_cap;

		free(ets);
		free(pfc);
		free(data);
	}

	/* if the dcbx field is filled in by the dcbx query then the
	 * kernel is supports IEEE mode, so make IEEE DCBX active by default.
	 */
	if (!dcbx || (dcbx_get_legacy_version(ifname) & ~MASK_DCBX_FORCE)) {
		tlvs->active = false;
	} else {
		tlvs->active = true;
		tlvs->pending = true;
	}

	return;
err_pfc:
	free(tlvs->ets->recl);
err_recl:
	free(tlvs->ets->cfgl);
err:
	free(tlvs->ets);
	free(tlvs->rx);
	free(tlvs);
	LLDPAD_WARN("%s: %s malloc failed.\n", __func__, ifname);
	return;
}

/*
 * ets_sm - Asymmetric State Machine for the ETS tlv
 */
static void ets_sm(struct etscfg_obj *localAdminParam,
		   struct etsrec_obj *remoteParam,
		   bool *state)
{
	int willing = localAdminParam->willing;

	if (willing && remoteParam)
		*state = RX_RECOMMEND;
	else if (!willing || !remoteParam)
		*state = INIT;
}

/*
 * cmp_mac_addrs - Compares 2 MAC addresses.
 * returns 1, if first_mac > second_mac; else 0
 */
static bool cmp_mac_addrs(u8 first_mac[], u8 second_mac[])
{
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		if (first_mac[i] == second_mac[i])
			continue;
		if (first_mac[i] < second_mac[i])
			return 0;
		return 1;
	}
	return 0;
}

/*
 * pfc_sm - Symmetric State Machine for the PFC tlv
 */
static void pfc_sm(struct ieee8021qaz_tlvs *tlvs)
{
	bool local_willing, remote_willing;
	bool remote_param, cmp_mac;

	local_willing = tlvs->pfc->local.willing;
	remote_willing = tlvs->pfc->remote.willing;
	remote_param = tlvs->pfc->remote_param;
	cmp_mac = cmp_mac_addrs(tlvs->local_mac, tlvs->remote_mac);

	if ((local_willing && !remote_willing && remote_param) ||
	    (local_willing && remote_willing && !cmp_mac))
		tlvs->pfc->current_state = RX_RECOMMEND;
	else if (!local_willing || !remote_param ||
		 (local_willing && remote_willing && cmp_mac))
		tlvs->pfc->current_state = INIT;
}

#ifdef LLDPAD_8021QAZ_DEBUG
void print_ets(struct ieee_ets *ets)
{
	int i;

	printf("ETS:\n");
	printf("\tcap %2x cbs %2x\n", ets->ets_cap, ets->cbs);

	printf("\tets tc_tx_bw: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_tx_bw[i]);
	printf("\n");

	printf("\tets tc_rx_bw: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_rx_bw[i]);
	printf("\n");

	printf("\tets tc_tsa: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_tsa[i]);
	printf("\n");

	printf("\tets prio_tc: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->prio_tc[i]);
	printf("\n");
}

void print_pfc(struct ieee_pfc *pfc)
{
	int i;

	printf("PFC:\n");
	printf("\t cap %2x en %2x\n", pfc->pfc_cap, pfc->pfc_en);
	printf("\t mbc %2x delay %i\n", pfc->mbc, pfc->delay);

	printf("\t requests: ");
	for (i = 0; i < 8; i++)
		printf("%llu ", pfc->requests[i]);
	printf("\n");

	printf("\t indications: ");
	for (i = 0; i < 8; i++)
		printf("%llu ", pfc->indications[i]);
	printf("\n");
}
#endif

/*
 * get_ieee_hw - Populates IEEE data structures with hardware DCB attributes.
 *
 * @ifname: interface name to query
 * @ets: pointer to copy returned ETS struct
 * @pfc: pointer to copy returned PFC struct
 * @app: pointer to copy concatenated APP entries
 * @cnt: number of app entries returned
 *
 * Returns nlmsg bytes size on success otherwise negative error code.
 */
static int get_ieee_hw(const char *ifname, struct ieee_ets **ets,
			struct ieee_pfc **pfc, struct app_prio **app,
			int *cnt)
{
	int err = 0;
	int rem;
	int itr = 0;
	struct sockaddr_nl dest_addr;
	static struct nl_handle *nlhandle;
	struct nl_msg *nlm;
	unsigned char *msg = NULL;
	struct nlmsghdr *hdr;
	struct nlattr *app_attr, *attr, *nattr;
	struct dcbmsg d = {
			   .dcb_family = AF_UNSPEC,
			   .cmd = DCB_CMD_IEEE_GET,
			   .dcb_pad = 0
			  };

	if (!nlhandle) {
		nlhandle = nl_handle_alloc();
		if (!nlhandle) {
			LLDPAD_WARN("%s: %s: nl_handle_alloc failed, %s\n",
				    __func__, ifname, nl_geterror());
			*cnt = 0;
			return -ENOMEM;
		}
		nl_socket_set_local_port(nlhandle, 0);
	}

	if (nl_connect(nlhandle, NETLINK_ROUTE) < 0) {
		LLDPAD_WARN("%s: %s nlconnect failed abort get ieee, %s\n",
			    __func__, ifname, nl_geterror());
		goto out1;
	}

	nlm = nlmsg_alloc_simple(RTM_GETDCB, NLM_F_REQUEST);
	if (!nlm) {
		err = -ENOMEM;
		goto out1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	nlmsg_set_dst(nlm, &dest_addr);

	err = nlmsg_append(nlm, &d, sizeof(d), NLMSG_ALIGNTO);
	if (err < 0)
		goto out;

	err = nla_put(nlm, DCB_ATTR_IFNAME, strlen(ifname)+1, ifname);
	if (err < 0)
		goto out;

	err = nl_send_auto_complete(nlhandle, nlm);
	if (err <= 0) {
		LLDPAD_WARN("%s: %s 802.1Qaz get app attributes failed\n",
			    __func__, ifname);
		goto out;
	}

	err = nl_recv(nlhandle, &dest_addr, &msg, NULL);
	if (err <= 0) {
		LLDPAD_WARN("%s: %s: nl_recv returned %d\n", __func__, ifname,
			    err);
		goto out;
	}

	hdr = (struct nlmsghdr *) msg;

	attr = nlmsg_find_attr(hdr, sizeof(d), DCB_ATTR_IEEE);
	if (!attr) {
		LLDPAD_WARN("%s: %s: nlmsg_find_attr failed\n",
			    __func__, ifname);
		goto out;
	}

	*app = malloc(sizeof(struct app_prio));
	if (*app == NULL) {
		err = -ENOMEM;
		goto out;
	}

	*ets = malloc(sizeof(struct ieee_ets));
	if (*ets == NULL) {
		err = -ENOMEM;
		free(*app);
		goto out;
	}

	*pfc = malloc(sizeof(struct ieee_pfc));
	if (*pfc == NULL) {
		err = -ENOMEM;
		free(*app);
		free(*ets);
		goto out;
	}

	memset(*pfc, 0, sizeof(struct ieee_pfc));
	memset(*ets, 0, sizeof(struct ieee_ets));
	memset(*app, 0, sizeof(struct app_prio));

	nla_for_each_nested(nattr, attr, rem) {
		if (nla_type(nattr) == DCB_ATTR_IEEE_APP_TABLE) {
			struct app_prio *this_app = *app;

			nla_for_each_nested(app_attr, nattr, rem) {
				struct dcb_app *data = nla_data(app_attr);

				LLDPAD_DBG("app %i %i %i\n",
					   data->selector,
					   data->protocol,
					   data->priority);

				this_app = realloc(this_app,
					      sizeof(struct app_prio) * itr +
					      sizeof(struct app_prio));
				if (!this_app) {
					free(this_app);
					free(*ets);
					free(*pfc);
					err = -ENOMEM;
					LLDPAD_WARN("%s: %s: realloc failed\n",
						    __func__, ifname);
					goto out;
				}
				this_app[itr].prs =
					(data->priority << 5) | data->selector;
				this_app[itr].pid = htons(data->protocol);
				itr++;
			}

			/* realloc may have moved app so reset it */
			*app = this_app;
		}

		if (nla_type(nattr) == DCB_ATTR_IEEE_ETS) {
			struct ieee_ets *nl_ets = nla_data(nattr);

			memcpy(*ets, nl_ets, sizeof(struct ieee_ets));
#ifdef LLDPAD_8021QAZ_DEBUG
			print_ets(nl_ets);
#endif
		}

		if (nla_type(nattr) == DCB_ATTR_IEEE_PFC) {
			struct ieee_pfc *nl_pfc = nla_data(nattr);

			memcpy(*pfc, nl_pfc, sizeof(struct ieee_pfc));
#ifdef LLDPAD_8021QAZ_DEBUG
			print_pfc(nl_pfc);
#endif
		}
	}

out:
	nlmsg_free(nlm);
	free(msg);
	nl_close(nlhandle);
out1:
	*cnt = itr;
	return err;
}

static int del_ieee_hw(const char *ifname, struct dcb_app *app_data)
{
	int err = 0;
	struct nlattr *ieee, *app;
	struct sockaddr_nl dest_addr;
	static struct nl_handle *nlhandle;
	struct nl_msg *nlm;
	struct dcbmsg d = {
			   .dcb_family = AF_UNSPEC,
			   .cmd = DCB_CMD_IEEE_DEL,
			   .dcb_pad = 0
			  };

	if (!nlhandle) {
		nlhandle = nl_handle_alloc();
		if (!nlhandle) {
			LLDPAD_WARN("%s: %s: nl_handle_alloc failed, %s\n",
				    __func__, ifname, nl_geterror());
			return -ENOMEM;
		}
		nl_socket_set_local_port(nlhandle, 0);
	}

	if (nl_connect(nlhandle, NETLINK_ROUTE) < 0) {
		LLDPAD_WARN("%s: %s nlconnect failed abort hardware set, %s\n",
			    __func__, ifname, nl_geterror());
		err = -EIO;
		goto out1;
	}

	nlm = nlmsg_alloc_simple(RTM_SETDCB, NLM_F_REQUEST);
	if (!nlm) {
		err = -ENOMEM;
		goto out2;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	nlmsg_set_dst(nlm, &dest_addr);

	err = nlmsg_append(nlm, &d, sizeof(d), NLMSG_ALIGNTO);
	if (err < 0)
		goto out;

	err = nla_put(nlm, DCB_ATTR_IFNAME, strlen(ifname)+1, ifname);
	if (err < 0)
		goto out;

	ieee = nla_nest_start(nlm, DCB_ATTR_IEEE);
	if (!ieee) {
		err = -ENOMEM;
		goto out;
	}
	if (app_data) {
		app = nla_nest_start(nlm, DCB_ATTR_IEEE_APP_TABLE);
		if (!app) {
			err = -ENOMEM;
			goto out;
		}

		err = nla_put(nlm, DCB_ATTR_IEEE_APP,
			      sizeof(*app_data), app_data);
		if (err < 0)
			goto out;
		nla_nest_end(nlm, app);
	}
	nla_nest_end(nlm, ieee);
	err = nl_send_auto_complete(nlhandle, nlm);
	if (err <= 0)
		LLDPAD_WARN("%s: %s 802.1Qaz set attributes failed\n",
			    __func__, ifname);

out:
	nlmsg_free(nlm);
out2:
	nl_close(nlhandle);
out1:
	return err;


}

static int set_ieee_hw(const char *ifname, struct ieee_ets *ets_data,
		       struct ieee_pfc *pfc_data, struct dcb_app *app_data)
{
	int err = 0;
	struct nlattr *ieee, *app;
	struct sockaddr_nl dest_addr;
	static struct nl_handle *nlhandle;
	struct nl_msg *nlm;
	struct dcbmsg d = {
			   .dcb_family = AF_UNSPEC,
			   .cmd = DCB_CMD_IEEE_SET,
			   .dcb_pad = 0
			  };

	if (!nlhandle) {
		nlhandle = nl_handle_alloc();
		if (!nlhandle) {
			LLDPAD_WARN("%s: %s: nl_handle_alloc failed, %s\n",
				    __func__, ifname, nl_geterror());
			return -ENOMEM;
		}
		nl_socket_set_local_port(nlhandle, 0);
	}

	if (!ets_data && !pfc_data && !app_data) {
		err = 0;
		goto out1;
	}

#ifdef LLDPAD_8021QAZ_DEBUG
	if (ets_data)
		print_ets(ets_data);
	if (pfc_data)
		print_pfc(pfc_data);
#endif

	if (nl_connect(nlhandle, NETLINK_ROUTE) < 0) {
		LLDPAD_WARN("%s: %s nlconnect failed abort hardware set, %s\n",
			    __func__, ifname, nl_geterror());
		err = -EIO;
		goto out1;
	}

	nlm = nlmsg_alloc_simple(RTM_SETDCB, NLM_F_REQUEST);
	if (!nlm) {
		err = -ENOMEM;
		goto out2;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	nlmsg_set_dst(nlm, &dest_addr);

	err = nlmsg_append(nlm, &d, sizeof(d), NLMSG_ALIGNTO);
	if (err < 0)
		goto out;

	err = nla_put(nlm, DCB_ATTR_IFNAME, strlen(ifname)+1, ifname);
	if (err < 0)
		goto out;

	ieee = nla_nest_start(nlm, DCB_ATTR_IEEE);
	if (!ieee) {
		err = -ENOMEM;
		goto out;
	}

	if (ets_data) {
		err = nla_put(nlm, DCB_ATTR_IEEE_ETS,
			      sizeof(*ets_data), ets_data);
		if (err < 0)
			goto out;
	}

	if (pfc_data) {
		err = nla_put(nlm, DCB_ATTR_IEEE_PFC,
			      sizeof(*pfc_data), pfc_data);
		if (err < 0)
			goto out;
	}
	if (app_data) {
		app = nla_nest_start(nlm, DCB_ATTR_IEEE_APP_TABLE);
		if (!app) {
			err = -ENOMEM;
			goto out;
		}

		err = nla_put(nlm, DCB_ATTR_IEEE_APP,
			      sizeof(*app_data), app_data);
		if (err < 0)
			goto out;
		nla_nest_end(nlm, app);
	}
	nla_nest_end(nlm, ieee);
	err = nl_send_auto_complete(nlhandle, nlm);
	if (err <= 0)
		LLDPAD_WARN("%s: %s 802.1Qaz set attributes failed\n",
			    __func__, ifname);

out:
	nlmsg_free(nlm);
out2:
	nl_close(nlhandle);
out1:
	return err;
}

static void ets_cfg_to_ieee(struct ieee_ets *ieee, struct etscfg_obj *cfg)
{
	int i;

	memcpy(ieee->tc_tx_bw, cfg->tc_bw, MAX_TCS);
	memcpy(ieee->tc_rx_bw, cfg->tc_bw, MAX_TCS);
	memcpy(ieee->tc_tsa, cfg->tsa_map, MAX_TCS);

	for (i = 0; i < MAX_USER_PRIORITIES; i++)
		ieee->prio_tc[i] = get_prio_map(cfg->prio_map, i);

	memcpy(ieee->tc_reco_bw, cfg->tc_bw, MAX_TCS);
	memcpy(ieee->tc_reco_tsa, cfg->tsa_map, MAX_TCS);

	for (i = 0; i < MAX_USER_PRIORITIES; i++)
		ieee->reco_prio_tc[i] = get_prio_map(cfg->prio_map, i);

	return;
}

static void ets_rec_to_ieee(struct ieee_ets *ieee, struct etsrec_obj *rec)
{
	int i;

	memcpy(ieee->tc_tx_bw, rec->tc_bw, MAX_TCS);
	memcpy(ieee->tc_rx_bw, rec->tc_bw, MAX_TCS);
	memcpy(ieee->tc_tsa, rec->tsa_map, MAX_TCS);

	for (i = 0; i < MAX_TCS; i++)
		ieee->prio_tc[i] = get_prio_map(rec->prio_map, i);

	memcpy(ieee->tc_reco_bw, rec->tc_bw, MAX_TCS);
	memcpy(ieee->tc_reco_tsa, rec->tsa_map, MAX_TCS);

	for (i = 0; i < MAX_TCS; i++)
		ieee->reco_prio_tc[i] = get_prio_map(rec->prio_map, i);

	return;
}

void run_all_sm(struct port *port, struct lldp_agent *agent)
{
	struct ieee8021qaz_tlvs *tlvs;
	struct ieee_ets *ets;
	struct ieee_pfc *pfc;
	struct pfc_obj *pfc_obj;

	if (agent->type != NEAREST_BRIDGE)
		return;

	tlvs = ieee8021qaz_data(port->ifname);
	if (!tlvs)
		return;

	ets_sm(tlvs->ets->cfgl, tlvs->ets->recr, &tlvs->ets->current_state);

	ets = malloc(sizeof(*ets));
	if (!ets) {
		LLDPAD_WARN("%s: %s: ets malloc failed\n",
			    __func__, port->ifname);
		return;
	}

	memset(ets, 0, sizeof(*ets));

	if (tlvs->ets->current_state == RX_RECOMMEND)
		ets_rec_to_ieee(ets, tlvs->ets->recr);
	else
		ets_cfg_to_ieee(ets, tlvs->ets->cfgl);

	pfc_sm(tlvs);

	if (tlvs->pfc->current_state == RX_RECOMMEND)
		pfc_obj = &tlvs->pfc->remote;
	else
		pfc_obj = &tlvs->pfc->local;

	pfc = malloc(sizeof(*pfc));
	if (!pfc) {
		LLDPAD_WARN("%s: %s: pfc malloc failed\n",
			    __func__, port->ifname);
		goto out;
	}

	memset(pfc, 0, sizeof(*pfc));

	pfc->pfc_en = pfc_obj->pfc_enable;
	pfc->mbc = pfc_obj->mbc;
	pfc->delay = pfc_obj->delay;

	if (ieee8021qaz_check_active(port->ifname)) {
		set_dcbx_mode(port->ifname,
			      DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_HOST);
		set_ieee_hw(port->ifname, ets, pfc, NULL);
		ieee8021qaz_app_sethw(port->ifname, &tlvs->app_head);
	}

out:
	free(pfc);
	free(ets);
}

/*
 * bld_ieee8021qaz_etscfg_tlv - builds the ETS Configuration TLV
 * Returns 1 on success, NULL if the TLV fail to build correctly.
 */
static struct unpacked_tlv *
bld_ieee8021qaz_etscfg_tlv(struct ieee8021qaz_tlvs *tlvs)
{
	struct ieee8021qaz_tlv_etscfg *etscfg;
	struct unpacked_tlv *tlv = create_tlv();
	int i = 0;

	if (!tlv)
		return NULL;

	etscfg = (struct ieee8021qaz_tlv_etscfg *)malloc(sizeof(*etscfg));
	if (!etscfg) {
		LLDPAD_WARN("%s: Failed to malloc etscfg\n", __func__);
		free(tlv);
		return NULL;
	}
	memset(etscfg, 0, sizeof(*etscfg));

	hton24(etscfg->oui, OUI_IEEE_8021);
	etscfg->subtype = LLDP_8021QAZ_ETSCFG;
	etscfg->wcrt = tlvs->ets->cfgl->willing << 7 |
		       tlvs->ets->cfgl->cbs << 6 |
		       (tlvs->ets->cfgl->max_tcs & 0x7);

	if (tlvs->ets->current_state == INIT) {
		etscfg->prio_map = htonl(tlvs->ets->cfgl->prio_map);
		for (i = 0; i < MAX_TCS; i++) {
			etscfg->tc_bw[i] = tlvs->ets->cfgl->tc_bw[i];
			etscfg->tsa_map[i] = tlvs->ets->cfgl->tsa_map[i];
		}
	} else {
		etscfg->prio_map = htonl(tlvs->ets->recr->prio_map);
		for (i = 0; i < MAX_TCS; i++) {
			etscfg->tc_bw[i] = tlvs->ets->recr->tc_bw[i];
			etscfg->tsa_map[i] = tlvs->ets->recr->tsa_map[i];
		}
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct ieee8021qaz_tlv_etscfg);
	tlv->info = (u8 *)etscfg;

	if (OUI_SUB_SIZE > tlv->length)
		goto error;

	return tlv;

error:
	if (tlv) {
		if (tlv->info)
			free(tlv->info);
		free(tlv);
	}
	LLDPAD_WARN("%s: Failed\n", __func__);
	return NULL;
}

/*
 * bld_ieee8021qaz_etsrec_tlv - builds the ETS Recommendation TLV
 * Returns 1 on success, NULL if the TLV fail to build correctly.
 */
struct unpacked_tlv *
bld_ieee8021qaz_etsrec_tlv(struct ieee8021qaz_tlvs *tlvs)
{
	struct ieee8021qaz_tlv_etsrec *etsrec;
	struct unpacked_tlv *tlv = create_tlv();
	int i = 0;

	if (!tlv)
		return NULL;

	etsrec = (struct ieee8021qaz_tlv_etsrec *)malloc(sizeof(*etsrec));
	if (!etsrec) {
		LLDPAD_WARN("%s: Failed to malloc etscfg\n", __func__);
		free(tlv);
		return NULL;
	}
	memset(etsrec, 0, sizeof(*etsrec));

	hton24(etsrec->oui, OUI_IEEE_8021);
	etsrec->subtype = LLDP_8021QAZ_ETSREC;
	etsrec->prio_map = htonl(tlvs->ets->recl->prio_map);

	for (i = 0; i < MAX_TCS; i++) {
		etsrec->tc_bw[i] = tlvs->ets->recl->tc_bw[i];
		etsrec->tsa_map[i] = tlvs->ets->recl->tsa_map[i];
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct ieee8021qaz_tlv_etsrec);
	tlv->info = (u8 *)etsrec;

	if (OUI_SUB_SIZE > tlv->length)
		goto error;

	return tlv;

error:
	if (tlv) {
		if (tlv->info)
			free(tlv->info);
		free(tlv);
	}
	LLDPAD_WARN("%s: Failed\n", __func__);
	return NULL;
}

/*
 * bld_ieee8021qaz_pfc_tlv - builds the PFC Control Configuration TLV
 * Returns unpacket tlv or NULL if the TLV fails to build correctly.
 */
static struct unpacked_tlv *
bld_ieee8021qaz_pfc_tlv(struct ieee8021qaz_tlvs *tlvs)
{
	struct ieee8021qaz_tlv_pfc *pfc;
	struct unpacked_tlv *tlv = create_tlv();

	if (!tlv)
		return NULL;

	pfc = (struct ieee8021qaz_tlv_pfc *)malloc(sizeof(*pfc));
	if (!pfc) {
		LLDPAD_WARN("%s: Failed to malloc pfc\n", __func__);
		free(tlv);
		return NULL;
	}

	memset(pfc, 0, sizeof(*pfc));

	hton24(pfc->oui, OUI_IEEE_8021);
	pfc->subtype = LLDP_8021QAZ_PFC;

	pfc->wmrc = tlvs->pfc->local.willing << 7 |
		    tlvs->pfc->local.mbc << 6 |
		    tlvs->pfc->local.pfc_cap;

	if (tlvs->pfc->current_state == INIT)
		pfc->pfc_enable = tlvs->pfc->local.pfc_enable;
	else
		pfc->pfc_enable = tlvs->pfc->remote.pfc_enable;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct ieee8021qaz_tlv_pfc);
	tlv->info = (u8 *)pfc;

	if (OUI_SUB_SIZE > tlv->length)
		goto error;

	return tlv;
error:
	if (tlv) {
		if (tlv->info)
			free(tlv->info);
		free(tlv);
	}
	LLDPAD_WARN("%s: Failed\n", __func__);
	return NULL;
}

/*
 * bld_ieee8021qaz_app_tlv - builds the APP TLV
 * Returns unacked tlv or NULL if the TLV fails to build correctly.
 */
static struct unpacked_tlv *
bld_ieee8021qaz_app_tlv(char *ifname)
{
	struct ieee8021qaz_tlv_app *app = NULL;
	struct unpacked_tlv *tlv;
	struct ieee_ets *ets = NULL;
	struct ieee_pfc *pfc = NULL;
	struct app_prio *data = NULL;
	__u8 *ptr;
	int cnt, err;

	tlv = create_tlv();
	if (!tlv)
		return NULL;

	err = get_ieee_hw(ifname, &ets, &pfc, &data, &cnt);
	if (!err) {
		LLDPAD_WARN("%s: %s: get_ieee_hw failed\n", __func__, ifname);
		goto error;
	}

	app = malloc(sizeof(*app) + (sizeof(*data) * cnt));
	if (!app) {
		LLDPAD_WARN("%s: Failed to malloc app\n", __func__);
		goto error;
	}

	memset(app, 0, sizeof(*app));
	hton24(app->oui, OUI_IEEE_8021);
	app->subtype = LLDP_8021QAZ_APP;

	ptr = (u8 *) app + sizeof(*app);
	memcpy(ptr, data, sizeof(*data) * cnt);

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct ieee8021qaz_tlv_app) + (cnt * 3);
	tlv->info = (u8 *)app;

	if (OUI_SUB_SIZE > tlv->length) {
		LLDPAD_WARN("%s: %s: tlv->length = %d, cnt=%d\n", __func__,
			    ifname, tlv->length, cnt);
		goto error;
	}

	free(ets);
	free(pfc);
	free(data);

	return tlv;

error:
	free(tlv);
	free(ets);
	free(pfc);
	free(app);
	free(data);
	LLDPAD_WARN("%s: Failed\n", __func__);
	return NULL;
}

/*
 * ieee8021qaz_bld_tlv - builds all IEEE8021QAZ TLVs
 * Returns 1 on success, NULL if any of the TLVs fail to build correctly.
 */
static struct packed_tlv *ieee8021qaz_bld_tlv(struct port *port,
					      struct lldp_agent *agent)
{
	struct ieee8021qaz_tlvs *data;
	struct packed_tlv *ptlv = NULL;
	struct unpacked_tlv *etscfg_tlv, *etsrec_tlv, *pfc_tlv, *app_tlv;
	size_t size;

	if (agent->type != NEAREST_BRIDGE)
		return NULL;

	data = ieee8021qaz_data(port->ifname);
	if (!data)
		return ptlv;

	etscfg_tlv = etsrec_tlv = pfc_tlv = app_tlv = NULL;

	if (!data->active)
		return ptlv;

	if (!is_tlv_txdisabled(port->ifname, agent->type, TLVID_8021(LLDP_8021QAZ_ETSCFG)))
		etscfg_tlv = bld_ieee8021qaz_etscfg_tlv(data);
	if (is_tlv_txenabled(port->ifname, agent->type, TLVID_8021(LLDP_8021QAZ_ETSREC)))
		etsrec_tlv = bld_ieee8021qaz_etsrec_tlv(data);
	if (!is_tlv_txdisabled(port->ifname, agent->type, TLVID_8021(LLDP_8021QAZ_PFC)))
		pfc_tlv = bld_ieee8021qaz_pfc_tlv(data);
	if (is_tlv_txenabled(port->ifname, agent->type, TLVID_8021(LLDP_8021QAZ_APP)))
		app_tlv = bld_ieee8021qaz_app_tlv(port->ifname);

	size = TLVSIZE(etscfg_tlv)
		+ TLVSIZE(etsrec_tlv)
		+ TLVSIZE(pfc_tlv)
		+ TLVSIZE(app_tlv);

	ptlv = create_ptlv();
	if (!ptlv)
		goto err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto err;

	ptlv->size = 0;
	PACK_TLV_AFTER(etscfg_tlv, ptlv, size, err);
	PACK_TLV_AFTER(etsrec_tlv, ptlv, size, err);
	PACK_TLV_AFTER(pfc_tlv, ptlv, size, err);
	PACK_TLV_AFTER(app_tlv, ptlv, size, err);
err:
	free_unpkd_tlv(etscfg_tlv);
	free_unpkd_tlv(etsrec_tlv);
	free_unpkd_tlv(pfc_tlv);
	free_unpkd_tlv(app_tlv);
	return ptlv;
}

/* LLDP_8021QAZ_MOD_OPS - GETTLV */
struct packed_tlv *ieee8021qaz_gettlv(struct port *port,
				      struct lldp_agent *agent)
{
	struct packed_tlv *ptlv = NULL;

	if (agent->type != NEAREST_BRIDGE)
		return NULL;

	/* Update TLV State Machines */
	run_all_sm(port, agent);
	/* Build TLVs */
	ptlv = ieee8021qaz_bld_tlv(port, agent);
	return ptlv;
}

static bool unpack_ieee8021qaz_tlvs(struct port *port,
				    struct lldp_agent *agent,
				    struct unpacked_tlv *tlv)
{
	/* Unpack tlvs and store in rx */
	struct ieee8021qaz_tlvs *tlvs;

	if (agent->type != NEAREST_BRIDGE) {
		LLDPAD_INFO("%s: %s: ignoring tlv from remote bridge\n",
			    __func__, port->ifname);
		return false;
	}

	tlvs = ieee8021qaz_data(port->ifname);

	/* Process */
	switch (tlv->info[OUI_SIZE]) {
	case IEEE8021QAZ_ETSCFG_TLV:
		if (tlvs->rx->etscfg == NULL) {
			tlvs->ieee8021qazdu |= RCVD_IEEE8021QAZ_TLV_ETSCFG;
			tlvs->rx->etscfg = tlv;
		} else {
			LLDPAD_WARN("%s: %s: 802.1Qaz Duplicate ETSCFG TLV\n",
				__func__, port->ifname);
			agent->rx.dupTlvs |= DUP_IEEE8021QAZ_TLV_ETSCFG;
			return false;
		}
		break;
	case IEEE8021QAZ_ETSREC_TLV:
		if (tlvs->rx->etsrec == NULL) {
			tlvs->ieee8021qazdu |= RCVD_IEEE8021QAZ_TLV_ETSREC;
			tlvs->rx->etsrec = tlv;
		} else {
			LLDPAD_WARN("%s: %s: 802.1Qaz Duplicate ETSREC TLV\n",
				__func__, port->ifname);
			agent->rx.dupTlvs |= DUP_IEEE8021QAZ_TLV_ETSREC;
			return false;
		}
		break;

	case IEEE8021QAZ_PFC_TLV:
		if (tlvs->rx->pfc == NULL) {
			tlvs->ieee8021qazdu |= RCVD_IEEE8021QAZ_TLV_PFC;
			tlvs->rx->pfc = tlv;
		} else {
			LLDPAD_WARN("%s: %s: 802.1Qaz Duplicate PFC TLV\n",
				__func__, port->ifname);
			agent->rx.dupTlvs |= DUP_IEEE8021QAZ_TLV_PFC;
			return false;
		}
		break;
	case IEEE8021QAZ_APP_TLV:
		if (tlvs->rx->app == NULL) {
			tlvs->ieee8021qazdu |= RCVD_IEEE8021QAZ_TLV_APP;
			tlvs->rx->app = tlv;
		} else {
			LLDPAD_WARN("%s: %s: 802.1Qaz Duplicate APP TLV\n",
				    __func__, port->ifname);
			agent->rx.dupTlvs |= DUP_IEEE8021QAZ_TLV_APP;
			return false;
		}
		break;
	default:
		LLDPAD_INFO("%s: %s: Unknown TLV 0x%04x\n", __func__,
			    port->ifname, tlv->info[OUI_SIZE]);
		return false;
	}
	return true;
}

static void clear_ieee8021qaz_rx(struct ieee8021qaz_tlvs *tlvs)
{
	if (!tlvs)
		return;

	if (!tlvs->rx)
		return;

	if (tlvs->rx->ieee8021qaz)
		tlvs->rx->ieee8021qaz = free_unpkd_tlv(tlvs->rx->ieee8021qaz);
	if (tlvs->rx->etscfg)
		tlvs->rx->etscfg = free_unpkd_tlv(tlvs->rx->etscfg);
	if (tlvs->rx->etsrec)
		tlvs->rx->etsrec = free_unpkd_tlv(tlvs->rx->etsrec);
	if (tlvs->rx->pfc)
		tlvs->rx->pfc = free_unpkd_tlv(tlvs->rx->pfc);
	if (tlvs->rx->app)
		tlvs->rx->app =	free_unpkd_tlv(tlvs->rx->app);

	free(tlvs->rx);
	tlvs->rx = NULL;
}

static void process_ieee8021qaz_etscfg_tlv(struct port *port)
{
	struct ieee8021qaz_tlvs *tlvs;
	u8 offset = 0;
	int i = 0;

	tlvs = ieee8021qaz_data(port->ifname);
	offset = OUI_SUB_SIZE;

	if (tlvs->ets->cfgr)
		free(tlvs->ets->cfgr);
	tlvs->ets->cfgr = malloc(sizeof(*tlvs->ets->cfgr));
	if (!tlvs->ets->cfgr) {
		LLDPAD_WARN("%s: %s: cfgr malloc failed\n",
			    __func__, port->ifname);
		return;
	}

	if (tlvs->rx->etscfg->info[offset] & BIT7)
		tlvs->ets->cfgr->willing = true;
	else
		tlvs->ets->cfgr->willing = false;

	if (tlvs->rx->etscfg->info[offset] & BIT6)
		tlvs->ets->cfgr->cbs = true;
	else
		tlvs->ets->cfgr->cbs = false;

	tlvs->ets->cfgr->max_tcs = tlvs->rx->etscfg->info[offset] & 0x07;

	/*Moving offset to PRIO_MAP */
	offset += 1;
	tlvs->ets->cfgr->prio_map = 0;
	for (i = 0; i < 4; i++) {
		u8 temp1 = 0, temp2 = 0;

		temp1 = (tlvs->rx->etscfg->info[offset] >> 4) & 0x0F;
		temp2 = tlvs->rx->etscfg->info[offset] & 0x0F;
		set_prio_map(&tlvs->ets->cfgr->prio_map, (2*i), temp1);
		set_prio_map(&tlvs->ets->cfgr->prio_map, ((2*i)+1), temp2);

		offset += 1;
	}

	for (i = 0; i < MAX_TCS; i++) {
		tlvs->ets->cfgr->tc_bw[i] = tlvs->rx->etscfg->info[offset];
		offset += 1;
	}

	for (i = 0; i < MAX_TCS; i++) {
		tlvs->ets->cfgr->tsa_map[i] = tlvs->rx->etscfg->info[offset];
		offset += 1;
	}

}

static void process_ieee8021qaz_etsrec_tlv(struct port *port)
{
	struct ieee8021qaz_tlvs *tlvs;
	u8 offset = 0;
	int i = 0;

	tlvs = ieee8021qaz_data(port->ifname);

	/* Bypassing OUI, SUBTYPE fields */
	offset = OUI_SUB_SIZE + 1;

	if (tlvs->ets->recr)
		memset(tlvs->ets->recr, 0, sizeof(*tlvs->ets->recr));
	else
		tlvs->ets->recr = malloc(sizeof(*tlvs->ets->recr));

	if (!tlvs->ets->recr)
		return;

	tlvs->ets->recr->prio_map = 0;
	for (i = 0; i < 4; i++) {
		u8 temp1 = 0, temp2 = 0;

		temp1 = (tlvs->rx->etsrec->info[offset] >> 4) & 0x0F;
		temp2 = tlvs->rx->etsrec->info[offset] & 0x0F;
		set_prio_map(&tlvs->ets->recr->prio_map, (2*i), temp1);
		set_prio_map(&tlvs->ets->recr->prio_map, ((2*i)+1), temp2);

		offset += 1;
	}

	for (i = 0; i < MAX_TCS; i++) {
		tlvs->ets->recr->tc_bw[i] = tlvs->rx->etsrec->info[offset];
		offset += 1;
	}

	for (i = 0; i < MAX_TCS; i++) {
		tlvs->ets->recr->tsa_map[i] = tlvs->rx->etsrec->info[offset];
		offset += 1;
	}
}

static void process_ieee8021qaz_pfc_tlv(struct port *port)
{
	struct ieee8021qaz_tlvs *tlvs;
	u8 offset = 0;

	tlvs = ieee8021qaz_data(port->ifname);

	/* Bypassing OUI, SUBTYPE fields */
	offset = OUI_SUB_SIZE;
	if (tlvs->rx->pfc->info[offset] & BIT7)
		tlvs->pfc->remote.willing = true;
	else
		tlvs->pfc->remote.willing = false;

	if (tlvs->rx->pfc->info[offset] & BIT6)
		tlvs->pfc->remote.mbc = true;
	else
		tlvs->pfc->remote.mbc = false;

	tlvs->pfc->remote.pfc_cap = tlvs->rx->pfc->info[offset] & 0x0F;

	offset += 1;
	tlvs->pfc->remote.pfc_enable = tlvs->rx->pfc->info[offset];

	tlvs->pfc->remote_param = true;
}

int ieee8021qaz_mod_app(struct app_tlv_head *head, int peer,
			u8 prio, u8 sel, u16 proto, u32 ops)
{
	struct app_obj *np;

	/* Search list for existing match and abort
	 * Mark entry for deletion if delete option supplied
	 */
	LIST_FOREACH(np, head, entry) {
		if (np->app.selector == sel &&
		    np->app.protocol == proto &&
		    np->app.priority == prio) {
			if (ops & op_delete)
				np->hw = IEEE_APP_DEL;
			return 1;
		}
	}

	if (ops & op_delete)
		return 1;

	/* Add new entry for APP data */
	np = calloc(1, sizeof(*np));
	if (!np) {
		LLDPAD_WARN("%s: memory alloc failure.\n", __func__);
		return -1;
	}

	np->peer = peer;
	np->hw = IEEE_APP_SET;
	np->app.priority = prio;
	np->app.selector = sel;
	np->app.protocol = proto;

	LIST_INSERT_HEAD(head, np, entry);
	return 0;
}

static void ieee8021qaz_app_reset(struct app_tlv_head *head)
{
	struct app_obj *np;

	LIST_FOREACH(np, head, entry) {
		if (np->peer)
			np->hw = IEEE_APP_DEL;
	}
}

static int __ieee8021qaz_app_sethw(char *ifname, struct app_tlv_head *head)
{
	struct app_obj *np, *np_tmp;
	int set = 0;

	LIST_FOREACH(np, head, entry) {
		if (np->hw != IEEE_APP_SET)
			continue;
		set = set_ieee_hw(ifname, NULL, NULL, &np->app);
		np->hw = IEEE_APP_DONE;
	}

	np = LIST_FIRST(head);
	while (np) {
		if (np->hw == IEEE_APP_DEL) {
			np_tmp = np;
			np = LIST_NEXT(np, entry);
			LIST_REMOVE(np_tmp, entry);
			set = del_ieee_hw(ifname, &np_tmp->app);
			free(np_tmp);
		} else {
			np = LIST_NEXT(np, entry);
		}
	}
	return set;
}

int ieee8021qaz_app_sethw(char *ifname, struct app_tlv_head *head)
{
	if (ieee8021qaz_check_active(ifname)) {
		set_dcbx_mode(ifname,
			      DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_HOST);
		return __ieee8021qaz_app_sethw(ifname, head);
	}
	return 0;
}

static void process_ieee8021qaz_app_tlv(struct port *port)
{
	struct ieee8021qaz_tlvs *tlvs;
	int offset = OUI_SUB_SIZE + 1;

	tlvs = ieee8021qaz_data(port->ifname);

	/* clear app priorities so old data is flushed */
	ieee8021qaz_app_reset(&tlvs->app_head);

	while (offset < tlvs->rx->app->length) {
		struct app_obj *np;
		int set = 0;
		u8 prio  = (tlvs->rx->app->info[offset] & 0xE0) >> 5;
		u8 sel = (tlvs->rx->app->info[offset] & 0x07);
		u16 proto = (tlvs->rx->app->info[offset + 1] << 8) |
			     tlvs->rx->app->info[offset + 2];

		/* Search list for existing match and mark set */
		LIST_FOREACH(np, &tlvs->app_head, entry) {
			if (np->app.selector == sel &&
			    np->app.protocol == proto &&
			    np->app.priority == prio) {
				np->hw = IEEE_APP_SET;
				set = 1;
				break;
			}
		}

		/* If APP data not found in LIST add APP entry */
		if (!set)
			ieee8021qaz_mod_app(&tlvs->app_head, 1,
					    prio, sel, proto, 0);
		offset += 3;
	}
}

static void ieee8021qaz_mibUpdateObjects(struct port *port)
{
	struct ieee8021qaz_tlvs *tlvs;

	tlvs = ieee8021qaz_data(port->ifname);

	if (tlvs->rx->etscfg) {
		process_ieee8021qaz_etscfg_tlv(port);
	} else if (tlvs->ets->cfgr) {
		free(tlvs->ets->cfgr);
		tlvs->ets->cfgr = NULL;
	}

	if (tlvs->rx->etsrec) {
		process_ieee8021qaz_etsrec_tlv(port);
	} else if (tlvs->ets->recr) {
		free(tlvs->ets->recr);
		tlvs->ets->recr = NULL;
	}

	if (tlvs->rx->pfc)
		process_ieee8021qaz_pfc_tlv(port);
	else if (tlvs->pfc)
		tlvs->pfc->remote_param = false;

	if (tlvs->rx->app)
		process_ieee8021qaz_app_tlv(port);
	else
		ieee8021qaz_app_reset(&tlvs->app_head);
}

/*
 * LLDP_8021_QAZ_MOD_OPS - RCHANGE
 *
 * TLVs not consumed on error otherwise it is either free'd or stored
 * internally in the module.
 */
int ieee8021qaz_rchange(struct port *port, struct lldp_agent *agent,
			struct unpacked_tlv *tlv)
{
	u8 oui[OUI_SIZE] = INIT_IEEE8021QAZ_OUI;
	struct ieee8021qaz_tlvs *qaz_tlvs;
	struct ieee8021qaz_unpkd_tlvs *rx;

	if (agent->type != NEAREST_BRIDGE)
		return 0;

	qaz_tlvs = ieee8021qaz_data(port->ifname);
	if (!qaz_tlvs)
		return SUBTYPE_INVALID;

	/*
	 * TYPE_1 mandatory and always before IEEE8021QAZ tlvs so
	 * we can use it to make the beginning of a IEEE8021QAZ PDU.
	 * Verifies that only a single IEEE8021QAZ tlv is present.
	 */
	if (tlv->type == TYPE_1) {
		clear_ieee8021qaz_rx(qaz_tlvs);
		rx = malloc(sizeof(*rx));
		memset(rx, 0, sizeof(*rx));
		qaz_tlvs->rx = rx;
		qaz_tlvs->ieee8021qazdu = 0;
	}

	/*
	 * TYPE_127 is for the Organizationally Specific TLVS
	 * More than 1 of this type is allowed.
	 */
	if (tlv->type == TYPE_127) {
		if (tlv->length < (OUI_SUB_SIZE))
			return TLV_ERR;

		if ((memcmp(tlv->info, &oui, OUI_SIZE) != 0))
			return SUBTYPE_INVALID;

		l2_packet_get_remote_addr(port->l2, qaz_tlvs->remote_mac);
		if (unpack_ieee8021qaz_tlvs(port, agent, tlv))
			return TLV_OK;
	}

	if (tlv->type == TYPE_0) {
		if (qaz_tlvs->active &&
		    dcbx_tlvs_rxed(qaz_tlvs->ifname, agent) &&
		   !qaz_tlvs->ieee8021qazdu) {
			qaz_tlvs->active = false;
			LLDPAD_INFO("IEEE DCBX on %s going INACTIVE\n",
				    qaz_tlvs->ifname);
		}

		if (qaz_tlvs->active) {
			/* If peer is DCBX, then go into RXTX mode
			 * if current configuration is RXOnly and
			 * not persistant (i.e. default)
			 */
			int adminstatus;
			if (qaz_tlvs->ieee8021qazdu &&
				get_config_setting(qaz_tlvs->ifname,
						   agent->type,
						   ARG_ADMINSTATUS,
						   &adminstatus,
						   CONFIG_TYPE_INT) &&
				get_lldp_agent_admin(qaz_tlvs->ifname,
						     agent->type) ==
						    enabledRxOnly) {
				adminstatus = enabledRxTx;
				if (set_config_setting(qaz_tlvs->ifname,
						       agent->type,
						       ARG_ADMINSTATUS,
						       &adminstatus,
						       CONFIG_TYPE_INT) ==
						       cmd_success)
					set_lldp_agent_admin(qaz_tlvs->ifname,
							     agent->type,
							     adminstatus);
			}
			if (qaz_tlvs->ieee8021qazdu)
				qaz_tlvs->pending = false;

			/* Update TLV State Machines */
			ieee8021qaz_mibUpdateObjects(port);
			run_all_sm(port, agent);
			clear_ieee8021qaz_rx(qaz_tlvs);
			somethingChangedLocal(port->ifname, agent->type);
		}
	}

	return TLV_OK;
}

static void ieee8021qaz_free_rx(struct ieee8021qaz_unpkd_tlvs *rx)
{
	if (!rx)
		return;

	if (rx->etscfg)
		rx->etscfg = free_unpkd_tlv(rx->etscfg);
	if (rx->etsrec)
		rx->etsrec = free_unpkd_tlv(rx->etsrec);
	if (rx->pfc)
		rx->pfc = free_unpkd_tlv(rx->pfc);
	if (rx->app)
		rx->app = free_unpkd_tlv(rx->app);

	return;
}

/*
 * LLDP_8021QAZ_MOD_OPS - MIBDELETEOBJECT
 *
 * ieee8021qaz_mibDeleteObject - deletes MIBs
 * Check if peer has ETS enabled
 *   - If yes, check if ETS TLV is present
 *     - If yes, set it as absent (delete it?)
 * Same for PFC and APP.
 */
u8 ieee8021qaz_mibDeleteObject(struct port *port, struct lldp_agent *agent)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (agent->type != NEAREST_BRIDGE)
		return 0;

	tlvs = ieee8021qaz_data(port->ifname);
	if (!tlvs)
		return 0;
	ieee8021qaz_free_rx(tlvs->rx);

	/* Reseting ETS Remote params */
	if (tlvs->ets) {
		if (tlvs->ets->recr) {
			free(tlvs->ets->recr);
			tlvs->ets->recr = NULL;
		}

		if (tlvs->ets->cfgr) {
			free(tlvs->ets->cfgr);
			tlvs->ets->cfgr = NULL;
		}
	}

	/* Reseting PFC Remote params */
	tlvs->pfc->remote_param = 0;
	tlvs->pfc->remote.willing = NULL;
	tlvs->pfc->remote.mbc = NULL;
	tlvs->pfc->remote.pfc_cap = 0;
	tlvs->pfc->remote.pfc_enable = 0;

	/* Clear peer Application data */
	ieee8021qaz_app_reset(&tlvs->app_head);

	/* Kick Tx State Machine */
	somethingChangedLocal(port->ifname, agent->type);
	return 0;
}

static struct ets_attrib *free_ets_tlv(struct ets_attrib *ets)
{
	if (ets) {
		free(ets->cfgl);
		free(ets->recl);
		free(ets->cfgr);
		free(ets->recr);
		free(ets);
		ets = NULL;
	}

	return NULL;
}

static struct pfc_attrib *free_pfc_tlv(struct pfc_attrib *pfc)
{
	if (pfc) {
		free(pfc);
		pfc = NULL;
	}

	return NULL;
}

static void ieee8021qaz_free_tlv(struct ieee8021qaz_tlvs *tlvs)
{
	struct app_obj *np;

	if (!tlvs)
		return;

	if (tlvs->ets)
		tlvs->ets = free_ets_tlv(tlvs->ets);
	if (tlvs->pfc)
		tlvs->pfc = free_pfc_tlv(tlvs->pfc);

	/* Remove _all_ existing application data */
	LIST_FOREACH(np, &tlvs->app_head, entry)
		np->hw = IEEE_APP_DEL;

	__ieee8021qaz_app_sethw(tlvs->ifname, &tlvs->app_head);

	return;
}

static void ieee8021qaz_free_data(struct ieee8021qaz_user_data *iud)
{
	struct ieee8021qaz_tlvs *id;
	if (iud) {
		while (!LIST_EMPTY(&iud->head)) {
			id = LIST_FIRST(&iud->head);
			LIST_REMOVE(id, entry);
			ieee8021qaz_free_tlv(id);
			ieee8021qaz_free_rx(id->rx);
			free(id->rx);
			free(id);
		}
	}
}

/* LLDP_8021QAZ_MOD_OPS - UNREGISTER */
void ieee8021qaz_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		ieee8021qaz_free_data(mod->data);
		free(mod->data);
	}

	free(mod);
}

/*
 * LLDP_8021QAZ_MOD_OPS - IFDOWN
 */
void ieee8021qaz_ifdown(char *device_name, struct lldp_agent *agent)
{
	struct port *port = NULL;
	struct ieee8021qaz_tlvs *tlvs;

	if (agent->type != NEAREST_BRIDGE)
		return;

	port = porthead;
	while (port != NULL) {
		if (!strncmp(device_name, port->ifname, MAX_DEVICE_NAME_LEN))
			break;
		port = port->next;
	}

	tlvs = ieee8021qaz_data(device_name);

	if (!tlvs)
		return;

	if (tlvs) {
		ieee8021qaz_free_rx(tlvs->rx);
		free(tlvs->rx);
		tlvs->rx = NULL;
	}
}

/*
 * LLDP_8021QAZ_MOD_OPS - TLVS_RXED
 */
int ieee8021qaz_tlvs_rxed(const char *ifname)
{
	struct ieee8021qaz_user_data *iud;
	struct ieee8021qaz_tlvs *tlv = NULL;

	iud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_8021QAZ);
	if (iud) {
		LIST_FOREACH(tlv, &iud->head, entry) {
			if (!strncmp(tlv->ifname, ifname, IFNAMSIZ))
				return !!tlv->ieee8021qazdu;
		}
	}

	return 0;
}

/*
 * LLDP_8021QAZ_MOD_OPS - CHECK_ACTIVE
 */
int ieee8021qaz_check_active(const char *ifname)
{
	struct ieee8021qaz_user_data *iud;
	struct ieee8021qaz_tlvs *tlv = NULL;

	iud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_8021QAZ);
	if (iud) {
		LIST_FOREACH(tlv, &iud->head, entry) {
			if (!strncmp(tlv->ifname, ifname, IFNAMSIZ))
				return tlv->active && !tlv->pending;
		}
	}

	return 0;
}
