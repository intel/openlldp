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
#include "lldp_8023.h"
#include "messages.h"
#include "config.h"
#include "lldp_8023_clif.h"
#include "lldp_8023_cmds.h"
#include "lldp_ethtool.h"
#include "lldp_mand_clif.h"

struct tlv_info_8023_maccfg {
	u8 oui[3];
	u8 sub;
	u8 neg;
	u16 adv;
	u16 mau;
} __attribute__ ((__packed__));

struct tlv_info_8023_maxfs {
	u8 oui[3];
	u8 sub;
	u16 mfs;
} __attribute__ ((__packed__));

struct tlv_info_8023_linkagg {
	u8 oui[3];
	u8 sub;
	u8 status;
	u32 portid;
} __attribute__ ((__packed__));

struct tlv_info_8023_powvmdi {
	u8 oui[3];
	u8 sub;
	u8 caps;
	u8 pairs;
	u8 class;
} __attribute__ ((__packed__));

struct tlv_info_8023_add_eth_caps {
	u8 oui[3];
	u8 sub;
	u16 preempt;
} __attribute__ ((__packed__));

static const struct lldp_mod_ops ieee8023_ops =  {
	.lldp_mod_register	= ieee8023_register,
	.lldp_mod_unregister	= ieee8023_unregister,
	.lldp_mod_gettlv	= ieee8023_gettlv,
	.lldp_mod_ifup		= ieee8023_ifup,
	.lldp_mod_ifdown	= ieee8023_ifdown,
	.lldp_mod_rchange	= ieee8023_rchange,
	.get_arg_handler	= ieee8023_get_arg_handlers,
};

static struct ieee8023_data *ieee8023_data(const char *ifname,
					   enum agent_type type,
					   struct ieee8023_user_data **p_ud)
{
	struct ieee8023_user_data *ud;
	struct ieee8023_data *bd = NULL;

	ud = find_module_user_data_by_id(&lldp_mod_head, LLDP_MOD_8023);
	if (p_ud)
		*p_ud = ud;

	if (ud) {
		LIST_FOREACH(bd, &ud->head, entry) {
			if (!strncmp(ifname, bd->ifname, IFNAMSIZ) &&
			    (type == bd->agenttype))
				return bd;
		}
	}
	return NULL;
}

/*
 * ieee8023_bld_maccfg_tlv - build the MAC/PHY Config Status TLV
 * @bd: the med data struct
 *
 * Returns 0 on success
 */
static int ieee8023_bld_maccfg_tlv(struct ieee8023_data *bd,
				   struct lldp_agent *agent)
{
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	struct tlv_info_8023_maccfg maccfg;

	/* free old one if it exists */
	FREE_UNPKD_TLV(bd, maccfg);

	/* mandatory for LLDP-MED */
	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      TLVID_8023(LLDP_8023_MACPHY_CONFIG_STATUS))) {
		goto out_err;
	}

	/* load from config */
	memset(&maccfg, 0, sizeof(maccfg));
	if (get_config_tlvinfo_bin(bd->ifname, agent->type,
				   TLVID_8023(LLDP_8023_MACPHY_CONFIG_STATUS),
				   &maccfg, sizeof(maccfg))) {
		hton24(maccfg.oui, OUI_IEEE_8023);
		maccfg.sub = LLDP_8023_MACPHY_CONFIG_STATUS;
		if (is_autoneg_supported(bd->ifname))
			maccfg.neg |= LLDP_8023_MACPHY_AUTONEG_SUPPORT;
		if (is_autoneg_enabled(bd->ifname))
			maccfg.neg |= LLDP_8023_MACPHY_AUTONEG_ENABLED;
		maccfg.adv = htons(get_maucaps(bd->ifname));
		maccfg.mau = htons(get_mautype(bd->ifname));
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(maccfg);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, &maccfg, tlv->length);
	bd->maccfg = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * ieee8023_bld_maxfs_tlv - build the Max Frame Size TLV
 * @bd: the med data struct
 *
 * Returns 0 on success
 */
static int ieee8023_bld_maxfs_tlv(struct ieee8023_data *bd,
				  struct lldp_agent *agent)
{
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	struct tlv_info_8023_maxfs maxfs;

	/* free old one if it exists */
	FREE_UNPKD_TLV(bd, maxfs);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      TLVID_8023(LLDP_8023_MAXIMUM_FRAME_SIZE))) {
		goto out_err;
	}

	/* load from config */
	memset(&maxfs, 0, sizeof(maxfs));
	if (get_config_tlvinfo_bin(bd->ifname, agent->type,
				   TLVID_8023(LLDP_8023_MAXIMUM_FRAME_SIZE),
				   &maxfs, sizeof(maxfs))) {
		hton24(maxfs.oui, OUI_IEEE_8023);
		maxfs.sub = LLDP_8023_MAXIMUM_FRAME_SIZE;
		maxfs.mfs = htons(get_mfs(bd->ifname));
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(maxfs);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, &maxfs, tlv->length);
	bd->maxfs = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * ieee8023_bld_linkagg_tlv - build the Link Aggregation TLV
 * @bd: the med data struct
 *
 * Returns 0 on success
 */
static int ieee8023_bld_linkagg_tlv(struct ieee8023_data *bd,
				    struct lldp_agent *agent)
{
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	struct tlv_info_8023_linkagg linkagg;

	/* free old one if it exists */
	FREE_UNPKD_TLV(bd, linkagg);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      TLVID_8023(LLDP_8023_LINK_AGGREGATION))) {
		goto out_err;
	}

	/* load from config */
	memset(&linkagg, 0, sizeof(linkagg));
	if (get_config_tlvinfo_bin(bd->ifname, agent->type,
				   TLVID_8023(LLDP_8023_LINK_AGGREGATION),
				   &linkagg, sizeof(linkagg))) {
		hton24(linkagg.oui, OUI_IEEE_8023);
		linkagg.sub = LLDP_8023_LINK_AGGREGATION;
		if (is_bond(bd->ifname)) {
			linkagg.status = (LLDP_8023_LINKAGG_CAPABLE |
					  LLDP_8023_LINKAGG_ENABLED);
			linkagg.portid =  htonl(get_master(bd->ifname));
		}
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(linkagg);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, &linkagg, tlv->length);
	bd->linkagg = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * ieee8023_bld_powvmdi_tlv - build the Power via MDI TLV
 * @bd: the med data struct
 *
 * Returns 0 on success
 */
static int ieee8023_bld_powvmdi_tlv(struct ieee8023_data *bd,
				    struct lldp_agent *agent)
{
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	struct tlv_info_8023_powvmdi powvmdi;

	/* free old one if it exists */
	FREE_UNPKD_TLV(bd, powvmdi);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      TLVID_8023(LLDP_8023_POWER_VIA_MDI))) {
		goto out_err;
	}

	/* not recommended for LLDP-MED */
	if (is_tlv_txenabled(bd->ifname, agent->type,
			     TLVID_MED(LLDP_MED_RESERVED))) {
		/* do not fail */
		goto out_err;
	}

	/* TODO: currently only supports config */
	memset(&powvmdi, 0, sizeof(powvmdi));
	if (get_config_tlvinfo_bin(bd->ifname, agent->type,
				   TLVID_8023(LLDP_8023_POWER_VIA_MDI),
				   &powvmdi, sizeof(powvmdi))) {
		goto out_err;
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(powvmdi);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	memcpy(tlv->info, &powvmdi, tlv->length);
	bd->powvmdi = tlv;
	rc = 0;
out_err:
	return rc;
}

static int ieee8023_config_read_add_frag_size(const char *ifname,
					      struct lldp_agent *agent)
{
	int add_frag_size, err;
	char arg_path[256];

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 TLVID_8023(LLDP_8023_ADD_ETH_CAPS), ARG_8023_ADD_FRAG_SIZE);

	err = get_config_setting(ifname, agent->type, arg_path, &add_frag_size,
				 CONFIG_TYPE_INT);
	if (err)
		return 0;

	return add_frag_size;
}

static u16 ieee8023_bld_preempt_status(struct ieee8023_data *bd,
				       struct lldp_agent *agent)
{
	int err, add_frag_size, config_add_frag_size;
	struct ieee8023_user_data *ud;
	struct ethtool_mm mm;
	u16 status = 0;

	ud = find_module_user_data_by_id(&lldp_mod_head, LLDP_MOD_8023);

	if (!ud->ethtool_sk)
		return status;

	err = ethtool_mm_get_state(ud->ethtool_sk, bd->ifname, &mm);
	if (err) {
		LLDPAD_ERR("%s: Failed to query ethtool MAC merge support: %d\n",
			   bd->ifname, err);
		return status;
	}

	config_add_frag_size = ieee8023_config_read_add_frag_size(bd->ifname,
								  agent);

	add_frag_size = ethtool_mm_frag_size_min_to_add(mm.rx_min_frag_size);
	if (add_frag_size < 0) {
		LLDPAD_ERR("%s: Kernel requests an RX min fragment size of %d which is too large to advertise\n",
			   bd->ifname, mm.rx_min_frag_size);
		return status;
	}

	if (config_add_frag_size < add_frag_size) {
		LLDPAD_WARN("%s: Configured addFragSize (%d) smaller than the minimum value requested by kernel (%d). Using the latter\n",
			    bd->ifname, config_add_frag_size, add_frag_size);
		config_add_frag_size = add_frag_size;
	}

	/* No error => supported */
	status |= LLDP_8023_ADD_ETH_CAPS_PREEMPT_SUPPORT |
		  LLDP_8023_ADD_ETH_CAPS_ADD_FRAG_SIZE(config_add_frag_size);

	if (mm.tx_enabled)
		status |= LLDP_8023_ADD_ETH_CAPS_PREEMPT_STATUS;

	if (mm.tx_active)
		status |= LLDP_8023_ADD_ETH_CAPS_PREEMPT_ACTIVE;

	return status;
}

/*
 * ieee8023_bld_add_eth_caps_tlv - build the Additional Ethernet Capabilities TLV
 * @bd: the med data struct
 *
 * Returns 0 on success
 */
static int ieee8023_bld_add_eth_caps_tlv(struct ieee8023_data *bd,
					 struct lldp_agent *agent)
{
	struct tlv_info_8023_add_eth_caps add_eth_caps;
	struct unpacked_tlv *tlv;

	/* free old one if it exists */
	FREE_UNPKD_TLV(bd, add_eth_caps);

	if (!is_tlv_txenabled(bd->ifname, agent->type,
			      TLVID_8023(LLDP_8023_ADD_ETH_CAPS)))
		return 0;

	hton24(add_eth_caps.oui, OUI_IEEE_8023);
	add_eth_caps.sub = LLDP_8023_ADD_ETH_CAPS;
	add_eth_caps.preempt = htons(ieee8023_bld_preempt_status(bd, agent));

	tlv = create_tlv();
	if (!tlv)
		return -ENOMEM;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(add_eth_caps);
	tlv->info = malloc(tlv->length);
	if (!tlv->info) {
		free(tlv);
		return -ENOMEM;
	}

	memcpy(tlv->info, &add_eth_caps, tlv->length);
	bd->add_eth_caps = tlv;

	return 0;
}

static void ieee8023_add_eth_caps_teardown(struct ieee8023_data *bd,
					   struct ieee8023_user_data *ud)
{
	/* On link down, the link partner might change to another one which
	 * does not advertise support for preemption, so disable what we've
	 * applied. However, do not disable preemption if it wasn't enabled
	 * by lldpad in the first place.
	 */
	if (bd->enabled_preemption) {
		ethtool_mm_change_tx_enabled(ud->ethtool_sk, bd->ifname, false,
					     false, 10);
		ethtool_mm_change_pmac_enabled(ud->ethtool_sk, bd->ifname,
					       false);
	}
}

static void ieee8023_free_tlv(struct ieee8023_data *bd)
{
	if (bd) {
		FREE_UNPKD_TLV(bd, maccfg);
		FREE_UNPKD_TLV(bd, powvmdi);
		FREE_UNPKD_TLV(bd, linkagg);
		FREE_UNPKD_TLV(bd, maxfs);
		FREE_UNPKD_TLV(bd, add_eth_caps);
	}
}

static int ieee8023_bld_tlv(struct ieee8023_data *bd, struct lldp_agent *agent)
{
	if (!port_find_by_ifindex(get_ifidx(bd->ifname)))
		return -EEXIST;

	if (ieee8023_bld_maccfg_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:ieee8023_bld_macfg_tlv() failed\n",
			   __func__, bd->ifname);
		return 0;
	}
	if (ieee8023_bld_powvmdi_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:ieee8023_bld_powvmdi_tlv() failed\n",
			   __func__, bd->ifname);
		return 0;
	}
	if (ieee8023_bld_linkagg_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:ieee8023_bld_linkagg_tlv() failed\n",
			   __func__, bd->ifname);
		return 0;
	}
	if (ieee8023_bld_maxfs_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:ieee8023_bld_maxfs_tlv() failed\n",
			   __func__, bd->ifname);
		return 0;
	}
	if (ieee8023_bld_add_eth_caps_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s:ieee8023_bld_add_eth_caps_tlv() failed\n",
			   __func__, bd->ifname);
		return 0;
	}
	return 0;
}

static void ieee8023_free_data(struct ieee8023_user_data *ud)
{
	struct ieee8023_data *bd;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			bd = LIST_FIRST(&ud->head);
			LIST_REMOVE(bd, entry);
			ieee8023_add_eth_caps_teardown(bd, ud);
			ieee8023_free_tlv(bd);
			free(bd);
		}

		if (ud->ethtool_sk)
			ethtool_sock_destroy(ud->ethtool_sk);
	}
}

struct packed_tlv *ieee8023_gettlv(struct port *port,
				   struct lldp_agent *agent)
{
	int size;
	struct ieee8023_data *bd;
	struct packed_tlv *ptlv = NULL;

	bd = ieee8023_data(port->ifname, agent->type, NULL);
	if (!bd)
		goto out_err;

	ieee8023_free_tlv(bd);
	if (ieee8023_bld_tlv(bd, agent)) {
		LLDPAD_DBG("%s:%s ieee8023_bld_tlv failed\n",
			__func__, port->ifname);
		goto out_err;
	}

	size = TLVSIZE(bd->maccfg) +
	       TLVSIZE(bd->powvmdi) +
	       TLVSIZE(bd->linkagg) +
	       TLVSIZE(bd->maxfs) +
	       TLVSIZE(bd->add_eth_caps);
	if (!size)
		goto out_err;

	ptlv = create_ptlv();
	if (!ptlv)
		goto out_err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	ptlv->size = 0;
	PACK_TLV_AFTER(bd->maccfg, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->powvmdi, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->linkagg, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->maxfs, ptlv, size, out_free);
	PACK_TLV_AFTER(bd->add_eth_caps, ptlv, size, out_free);
	return ptlv;
out_free:
	free_pkd_tlv(ptlv);
out_err:
	LLDPAD_DBG("%s:%s: failed\n", __func__, port->ifname);
	return NULL;

}


void ieee8023_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct ieee8023_user_data *ud;
	struct ieee8023_data *bd;

	bd = ieee8023_data(ifname, agent->type, &ud);
	if (!bd)
		goto out_err;

	LIST_REMOVE(bd, entry);
	ieee8023_add_eth_caps_teardown(bd, ud);
	ieee8023_free_tlv(bd);
	free(bd);
	LLDPAD_INFO("%s:port %s removed\n", __func__, ifname);
	return;
out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname);

	return;
}

void ieee8023_ifup(char *ifname, struct lldp_agent *agent)
{
	struct ieee8023_data *bd;
	struct ieee8023_user_data *ud;

	bd = ieee8023_data(ifname, agent->type, NULL);
	if (bd) {
		LLDPAD_INFO("%s:%s exists\n", __func__, ifname);
		goto out_err;
	}

	/* not found, alloc/init per-port tlv data */
	bd = (struct ieee8023_data *) malloc(sizeof(*bd));
	if (!bd) {
		LLDPAD_INFO("%s:%s malloc %zu failed\n",
			 __func__, ifname, sizeof(*bd));
		goto out_err;
	}
	memset(bd, 0, sizeof(struct ieee8023_data));
	STRNCPY_TERMINATED(bd->ifname, ifname, IFNAMSIZ);
	bd->agenttype = agent->type;

	if (ieee8023_bld_tlv(bd, agent)) {
		LLDPAD_INFO("%s:%s mand_bld_tlv failed\n", __func__, ifname);
		free(bd);
		goto out_err;
	}

	ud = find_module_user_data_by_id(&lldp_mod_head, LLDP_MOD_8023);
	LIST_INSERT_HEAD(&ud->head, bd, entry);
	LLDPAD_INFO("%s:port %s added\n", __func__, ifname);
	return;
out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname);
	return;
}

static void ieee8023_rchange_add_eth_caps(struct ieee8023_data *bd,
					  struct ieee8023_user_data *ud,
					  u8 *buf, int len)
{
	bool lp_supported, lp_enabled, lp_active;
	struct ethtool_mm mm;
	u32 lp_min_frag_size;
	u8 lp_add_frag_size;
	u8 tmp[2] = {};
	u16 preempt;
	int err;

	memcpy(tmp, buf, MIN(len, 2));
	preempt = ntohs(*((u16 *)tmp));

	lp_supported = !!(preempt & LLDP_8023_ADD_ETH_CAPS_PREEMPT_SUPPORT);
	lp_enabled = !!(preempt & LLDP_8023_ADD_ETH_CAPS_PREEMPT_STATUS);
	lp_active = !!(preempt & LLDP_8023_ADD_ETH_CAPS_PREEMPT_ACTIVE);
	lp_add_frag_size = LLDP_8023_ADD_ETH_CAPS_ADD_FRAG_SIZE_X(preempt);
	lp_min_frag_size = ethtool_mm_frag_size_add_to_min(lp_add_frag_size);

	LLDPAD_INFO("%s: Link partner preemption capability %ssupported\n",
		    bd->ifname, lp_supported ? "" : "not ");
	LLDPAD_INFO("%s: Link partner preemption capability %senabled\n",
		    bd->ifname, lp_enabled ? "" : "not ");
	LLDPAD_INFO("%s: Link partner preemption capability %sactive\n",
		    bd->ifname, lp_active ? "" : "not ");
	LLDPAD_INFO("%s: Link partner minimum fragment size: %d octets\n",
		    bd->ifname, lp_min_frag_size);

	if (!lp_supported || !ud->ethtool_sk)
		return;

	err = ethtool_mm_get_state(ud->ethtool_sk, bd->ifname, &mm);
	if (err) {
		LLDPAD_ERR("%s: Failed to query ethtool MAC merge support: %d\n",
			   bd->ifname, err);
		return;
	}

	/* In case the pMAC is not powered on, power it up now so that
	 * it responds to SMD-V frames initiated by the link partner,
	 * who may have enabled their verification state machine upon
	 * seeing our advertisements
	 */
	if (!mm.pmac_enabled) {
		err = ethtool_mm_change_pmac_enabled(ud->ethtool_sk, bd->ifname,
						     true);
		if (err) {
			LLDPAD_ERR("%s: Failed to enable pMAC RX: %d\n",
				   bd->ifname, err);
			return;
		}
	}

	/* Make sure that our TX is configured to use what minimum fragment
	 * size the link partner has requested
	 */
	if (mm.tx_min_frag_size != lp_min_frag_size) {
		err = ethtool_mm_change_tx_min_frag_size(ud->ethtool_sk,
							 bd->ifname,
							 lp_min_frag_size);
		if (err) {
			LLDPAD_ERR("%s: Failed to change TX min fragment size: %d\n",
				   bd->ifname, err);
			return;
		}
	}

	/* If both we and the link partner support frame preemption, we
	 * automatically turn our TX side on regardless of what the link
	 * partner may do. Since we request verification, preemption will
	 * only become active once the verification process succeeds
	 * (the link partner ACKs our handshake). Using the largest interval
	 * between verification attempts permitted by our hardware allows
	 * the link partner a bit of wiggle room to delay enabling its pMAC
	 * (which responds to our verification requests).
	 */
	if (!mm.tx_enabled || !mm.verify_enabled ||
	    mm.verify_time != mm.max_verify_time) {
		LLDPAD_INFO("%s: initiating MM verification with a retry interval of %d ms...\n",
			    bd->ifname, mm.max_verify_time);

		err = ethtool_mm_change_tx_enabled(ud->ethtool_sk, bd->ifname,
						   true, true,
						   mm.max_verify_time);
		if (err) {
			LLDPAD_ERR("%s: Failed to enable TX preemption: %d\n",
				   bd->ifname, err);
			return;
		}
	}

	bd->enabled_preemption = true;
}

/*
 * ieee8023_rchange: process received IEEE 802.3 TLV LLDPDU
 *
 * TLV not consumed on error
 */
int ieee8023_rchange(struct port *port, struct lldp_agent *agent,
		     struct unpacked_tlv *tlv)
{
	struct ieee8023_user_data *ud;
	struct ieee8023_data *bd;
	u8 subtype;
	u8 *oui;

	if (agent->type != NEAREST_BRIDGE)
		return SUBTYPE_INVALID;

	bd = ieee8023_data(port->ifname, agent->type, &ud);
	if (!bd)
		return SUBTYPE_INVALID;

	if (tlv->type != TYPE_127)
		return SUBTYPE_INVALID;

	if (tlv->length < OUI_SUB_SIZE)
		return TLV_ERR;

	oui = tlv->info;
	if (ntoh24(oui) != OUI_IEEE_8023)
		return SUBTYPE_INVALID;

	subtype = *(tlv->info + OUI_SIZE);
	switch (subtype) {
	case LLDP_8023_MACPHY_CONFIG_STATUS:
	case LLDP_8023_POWER_VIA_MDI:
	case LLDP_8023_LINK_AGGREGATION:
	case LLDP_8023_MAXIMUM_FRAME_SIZE:
		/* We don't need to store the TLV, so free it */
		free_unpkd_tlv(tlv);
		return TLV_OK;
	case LLDP_8023_ADD_ETH_CAPS:
		ieee8023_rchange_add_eth_caps(bd, ud, tlv->info + OUI_SUB_SIZE,
					      tlv->length - OUI_SUB_SIZE);
		/* We don't need to store the TLV, so free it */
		free_unpkd_tlv(tlv);
		return TLV_OK;
	}

	return SUBTYPE_INVALID;
}

struct lldp_module *ieee8023_register(void)
{
	struct lldp_module *mod;
	struct ieee8023_user_data *ud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("failed to malloc LLDP 802.3 module data\n");
		goto out_err;
	}
	ud = malloc(sizeof(struct ieee8023_user_data));
	if (!ud) {
		free(mod);
		LLDPAD_ERR("failed to malloc LLDP 802.3 module user data\n");
		goto out_err;
	}

	/* May return NULL if CONFIG_ETHTOOL_NETLINK is disabled,
	 * which isn't fatal
	 */
	ud->ethtool_sk = ethtool_sock_create();
	if (!ud->ethtool_sk)
		LLDPAD_WARN("Failed to create ethtool netlink socket\n");

	LIST_INIT(&ud->head);
 	mod->id = LLDP_MOD_8023;
	mod->ops = &ieee8023_ops;
	mod->data = ud;
	LLDPAD_INFO("%s:done\n", __func__);
	return mod;
out_err:
	LLDPAD_INFO("%s:failed\n", __func__);
	return NULL;

}

void ieee8023_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		ieee8023_free_data((struct ieee8023_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_INFO("%s:done\n", __func__);
}
