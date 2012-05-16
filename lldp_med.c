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
#include "lldp_med.h"
#include "messages.h"
#include "config.h"
#include "libconfig.h"
#include "lldp_mand_clif.h"
#include "lldp_med_cmds.h"

extern struct lldp_head lldp_head;

struct tlv_info_medcaps {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u16 medcaps;
	u8 devtype;
} __attribute__ ((__packed__));

struct tlv_info_netpoli {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 apptype;
	u16 unknown:1;
	u16 tagged:1;
	u16 reserved:1;
	u16 vid:12;
	u16 priority:3;
	u16 dscp:6;
} __attribute__ ((__packed__));

struct tlv_info_extpvm {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 powtype:2;
	u8 powsrc:2;
	u8 powprio:4;
	u16 powval;
} __attribute__ ((__packed__));

struct tlv_info_locid {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 format;
	union {
		u8 coord[16];
		u8 civic[256];
		u8 ecselin[25];
	} lci;
} __attribute__ ((__packed__));

static const struct lldp_mod_ops med_ops =  {
	.lldp_mod_register	= med_register,
	.lldp_mod_unregister	= med_unregister,
	.lldp_mod_gettlv	= med_gettlv,
	.lldp_mod_ifup		= med_ifup,
	.lldp_mod_ifdown	= med_ifdown,
	.get_arg_handler	= med_get_arg_handlers,
};

static struct med_data *med_data(const char *ifname, enum agent_type type)
{
	struct med_user_data *mud;
	struct med_data *md = NULL;

	mud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_MED);
	if (mud) {
		LIST_FOREACH(md, &mud->head, entry) {
			if (!strncmp(ifname, md->ifname, IFNAMSIZ) &&
			    (type == md->agenttype))
				return md;
		}
	}
	return NULL;
}

/* TODO : check config for optional caps */
static u16 med_get_caps(u8 devtype)
{
	u16 medcaps = 0;

	switch(devtype) {
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
		medcaps = (LLDP_MED_CAPABILITY_CAPAPILITIES |
			   LLDP_MED_CAPABILITY_INVENTORY);
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
		medcaps = (LLDP_MED_CAPABILITY_CAPAPILITIES |
			   LLDP_MED_CAPABILITY_INVENTORY);
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
		medcaps = (LLDP_MED_CAPABILITY_CAPAPILITIES |
			   LLDP_MED_CAPABILITY_INVENTORY |
			   LLDP_MED_CAPABILITY_LOCATION_ID);
		break;
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		LLDPAD_DBG("%s:WARNING:NETWORK_CONNECTIVITY is"
			   "supported for bridge only\n", __func__);
		medcaps = (LLDP_MED_CAPABILITY_CAPAPILITIES |
			   LLDP_MED_CAPABILITY_NETWORK_POLICY |
			   LLDP_MED_CAPABILITY_LOCATION_ID);
		break;
	case LLDP_MED_DEVTYPE_NOT_DEFINED:
	default:
		LLDPAD_DBG("%s:devtype %d not supported\n",
				__func__, devtype);
		break;
	}
	return medcaps;
}

/*
 * med_bld_medcaps_tlv - build the LLDP-MED Capabilities TLV
 * @md: the med data struct
 *
 * Try to load the med caps from the config if it exists, otherwise
 * build the med caps tlv from the scratch
 *
 * Returns 0 on success
 */
static int med_bld_medcaps_tlv(struct med_data *md,
			       struct lldp_agent *agent)
{
	int rc = EPERM;
	struct tlv_info_medcaps medcaps;
	struct unpacked_tlv *tlv = NULL;

	/* free old one if it exists */
	FREE_UNPKD_TLV(md, medcaps);

	/* must be enabled */
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_CAPABILITIES))) {
		LLDPAD_DBG("%s:%s:MED Caps is not enabled\n",
			__func__, md->ifname);
		rc = 0;
		goto out_err;
	}

	/* load cap tlv info from config */
	memset(&medcaps, 0, sizeof(medcaps));
	if (get_config_tlvinfo_bin(md->ifname, agent->type,
				   TLVID_MED(LLDP_MED_CAPABILITIES),
				   &medcaps, sizeof(medcaps))) {
		LLDPAD_DBG("%s:%s:Build MED Caps as Endpoint Class I\n",
			__func__, md->ifname);
		goto out_bld;
	}

	/* validate the data loaded */
	if (LLDP_MED_DEVTYPE_DEFINED(medcaps.devtype) &&
	    (medcaps.devtype == get_med_devtype(md->ifname, agent->type))) {
		LLDPAD_DBG("%s:%s:MED Caps loaded from config as type %d\n",
			__func__, md->ifname, medcaps.devtype);
		goto out_create;
	}
	LLDPAD_DBG("%s:%s:Load MED Caps is invalid\n",
		__func__, md->ifname);

out_bld:
	/* Not in config, build from scratch */
	hton24(medcaps.oui, OUI_TIA_TR41);
	medcaps.subtype = LLDP_MED_CAPABILITIES;
	medcaps.devtype = get_med_devtype(md->ifname, agent->type);
	medcaps.medcaps = htons(med_get_caps(medcaps.devtype));

out_create:
	tlv = create_tlv();
	if (!tlv) {
		rc = ENOMEM;
		goto out_err;
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(medcaps);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		rc = ENOMEM;
		goto out_err;
	}
	memcpy(tlv->info, &medcaps, tlv->length);
	md->medcaps = tlv;
	set_med_devtype(md->ifname, agent->type, medcaps.devtype);
	set_config_tlvinfo_bin(md->ifname, agent->type,
			       TLVID_MED(LLDP_MED_CAPABILITIES),
			       &medcaps, sizeof(medcaps));
	rc = 0;
out_err:
	return rc;
}

#define SYSFS_INV_PATH	"/sys/class/dmi/id"
#define PROC_INV_PATH	"/proc/sys/kernel"
#define PATH_INV_HWREV		SYSFS_INV_PATH "/board_version"
#define PATH_INV_FWREV		SYSFS_INV_PATH "/bios_version"
#define PATH_INV_SWREV		PROC_INV_PATH "/osrelease"
#define PATH_INV_MANUFACTURER	SYSFS_INV_PATH "/sys_vendor"
#define PATH_INV_SERIAL		SYSFS_INV_PATH "/product_uuid"
#define PATH_INV_MODELNAME	SYSFS_INV_PATH "/product_name"
#define PATH_INV_ASSETID	SYSFS_INV_PATH "/chassis_serial"

/*
 * TODO: If supports IETF RFC 2737
 */
int med_read_inventory(u8 subtype, char *buf, size_t size)
{
	char path[256];
	struct utsname uts;
	FILE *f = NULL;

	memset(buf, 0, size);
	memset(path, 0, sizeof(path));
	switch (subtype) {
	case LLDP_MED_INV_HWREV:
		strncpy(path, PATH_INV_HWREV, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_FWREV:
		strncpy(path, PATH_INV_FWREV, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_SWREV:
		if (!uname(&uts)) {
			strncpy(buf, uts.release, size - 1);
			goto out_err;
		}
		LLDPAD_DBG("%s: uname() failed for %d, try"
			" proc fs\n", __func__, subtype);
		strncpy(path, PATH_INV_SWREV, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_SERIAL:
		strncpy(path, PATH_INV_SERIAL, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_MANUFACTURER:
		strncpy(path, PATH_INV_MANUFACTURER, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_MODELNAME:
		strncpy(path, PATH_INV_MODELNAME, sizeof(path) - 1);
		break;
	case LLDP_MED_INV_ASSETID:
		strncpy(path, PATH_INV_ASSETID, sizeof(path) - 1);
		break;
	default:
		LLDPAD_DBG("%s: unknown inventory subtype %d\n",
			__func__, subtype);
		goto out_err;
	}
 	f = fopen(path, "r");
	if (!f) {
		LLDPAD_DBG("%s: fopen(%s) failed for type %d\n",
			__func__, path, subtype);
		goto out_err;
	}
	if (!fgets(buf, size, f)) {
		LLDPAD_DBG("%s: fgets(%s) failed for type %d\n",
			__func__, path, subtype);
		memset(buf, 0, size);
	}
	fclose(f);
out_err:
	return strlen(buf);
}

/*
 * med_bld_invtlv - builds inventory tlv by subtype
 * @md: the med data struct
 * @subtype: LLDP-MED inventory tlv subtype
 */
static struct unpacked_tlv *med_bld_invtlv(struct med_data *md,
					   struct lldp_agent *agent,
					   u8 subtype)
{
	int length;
	u8 desc[33];
	struct unpacked_tlv *tlv = NULL;

	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(subtype))) {
		LLDPAD_DBG("%s:%s:subtype %d tx disabled\n",
			__func__, md->ifname, subtype);
		goto out_err;
	}

	length = med_read_inventory(subtype, (char *)desc, sizeof(desc));
	if (!length) {
		LLDPAD_DBG("%s:%s:med_read_inventory(%d) failed\n",
			__func__, md->ifname, subtype);
		goto out_err;
	}
	if (desc[length - 1] == '\n')
		length--;

	tlv = create_tlv();
	if (!tlv) {
		LLDPAD_DBG("%s:%s:creat_tlv(%d) failed\n",
			__func__, md->ifname, subtype);
		goto out_err;
	}
	memset(tlv, 0, sizeof(struct unpacked_tlv));

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = length + OUI_SUB_SIZE;
	tlv->info = (u8 *) malloc(tlv->length);
	if (!tlv->info) {
		free(tlv);
		tlv = NULL;
		goto out_err;
	}
	hton24(tlv->info, OUI_TIA_TR41);
	tlv->info[OUI_SIZE] = subtype;
	memcpy(&tlv->info[OUI_SUB_SIZE], desc, length);

out_err:
	return tlv;
}

/*
 * med_bld_inventory_tlv - builds all inventory tlvs
 * @md: the med data struct
 *
 */
static int med_bld_inventory_tlv(struct med_data *md,
				 struct lldp_agent *agent)
{
	FREE_UNPKD_TLV(md, inv_hwrev);
	FREE_UNPKD_TLV(md, inv_fwrev);
	FREE_UNPKD_TLV(md, inv_swrev);
	FREE_UNPKD_TLV(md, inv_serial);
	FREE_UNPKD_TLV(md, inv_manufacturer);
	FREE_UNPKD_TLV(md, inv_modelname);
	FREE_UNPKD_TLV(md, inv_assetid);
	md->inv_hwrev = med_bld_invtlv(md, agent, LLDP_MED_INV_HWREV);
	md->inv_fwrev = med_bld_invtlv(md, agent, LLDP_MED_INV_FWREV);
	md->inv_swrev = med_bld_invtlv(md, agent, LLDP_MED_INV_SWREV);
	md->inv_serial = med_bld_invtlv(md, agent, LLDP_MED_INV_SERIAL);
	md->inv_manufacturer = med_bld_invtlv(md, agent, LLDP_MED_INV_MANUFACTURER);
	md->inv_modelname = med_bld_invtlv(md, agent, LLDP_MED_INV_MODELNAME);
	md->inv_assetid = med_bld_invtlv(md, agent, LLDP_MED_INV_ASSETID);
	return 0;
}

static int med_is_pd(const char *ifname)
{
	LLDPAD_DBG("%s:%s: TODO\n", __func__, ifname);
	return 0;

}

static int med_is_pse(const char *ifname)
{
	LLDPAD_DBG("%s:%s: TODO\n", __func__, ifname);
	return 0;
}

/*
 * med_bld_powvmdi_tlv - builds power via mdi tlv
 * @port: the port associated
 *
 * Returns 0 for success or error code for failure
 *
 * TODO:
 * When Extended Power via MDI TLV is enabled, it is recommended
 * by the spec ANSI-TIA-1057 Clause 9.2.4 to to disable 802.3AB
 * Optional Power via MDI TLV.
 *
 */
static int med_bld_powvmdi_tlv(struct med_data *md,
			       struct lldp_agent *agent)
{
	int rc = EINVAL;
	int devtype;
	int mandatory = 0;
	struct tlv_info_extpvm extpvm;
	struct unpacked_tlv *tlv = NULL;

	/* free old one if it exists */
	FREE_UNPKD_TLV(md, extpvm);

	devtype = get_med_devtype(md->ifname, agent->type);
	switch (devtype) {
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		mandatory = med_is_pse(md->ifname);
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
		mandatory = med_is_pd(md->ifname);
		break;
	default:
		LLDPAD_DBG("%s:%s: Unknown device type %d\n",
			__func__, md->ifname, devtype);
		rc = EINVAL;
		goto out_err;
	}

	if (!mandatory) {
		LLDPAD_DBG("%s:%s: No need to send Extended Power via MDI TLV\n",
			__func__, md->ifname);
		rc = 0;
		goto out_err;
	}
	/* Mandatory */
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_EXTENDED_PVMDI))) {
		LLDPAD_DBG("%s:%s: Must enable Extended Power via MDI TLV as it"
			" mandatory for device type %d\n",
			__func__, md->ifname, devtype);
		rc = EPERM;
		goto out_err;
	}
	/* Load from config */
	if (get_config_tlvinfo_bin(md->ifname, agent->type,
				   TLVID_MED(LLDP_MED_NETWORK_POLICY),
				   &extpvm, sizeof(extpvm))) {
		LLDPAD_DBG("%s:%s: Must configure Extended Power via MDI TLV as "
			" currently it has to be manually configured\n",
			__func__, md->ifname);
		rc = EINVAL;
		goto out_err;
	}
	/* disable Optional Power via MDI */
	tlv_disabletx(md->ifname, agent->type,
		      TLVID_8023(LLDP_8023_POWER_VIA_MDI));

	/* We should have a valid tlv_info_extpvm here */
	if (extpvm.subtype != LLDP_MED_EXTENDED_PVMDI) {
		LLDPAD_DBG("%s:%s: Wrong subtype %d: should be %d\n",
			__func__, md->ifname, extpvm.subtype, LLDP_MED_EXTENDED_PVMDI);
		rc = EINVAL;
		goto out_err;
	}

	tlv = create_tlv();
	if (!tlv) {
		rc = ENOMEM;
		goto out_err;
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(extpvm);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		rc = ENOMEM;
		goto out_err;
	}
	memcpy(tlv->info, &extpvm, tlv->length);
	md->extpvm = tlv;
	rc = 0;
out_err:
	return rc;
}

/*
 * med_bld_locid_tlv - builds location id  tlv
 * @md: the med data struct
 *
 * Returns 0 for success or error code for failure
 *
 * TODO: currently only supports load from config, will not transmit if
 * if it's not configured
 *
 */
static int med_bld_locid_tlv(struct med_data *md,
			     struct lldp_agent *agent)
{
	int rc = 0;
	size_t length;
	char *locstr = NULL;
	struct tlv_info_locid locid;
	struct unpacked_tlv *tlv = NULL;

	/* free old one if it exists */
	FREE_UNPKD_TLV(md, locid);

	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_LOCATION_ID))) {
		LLDPAD_DBG("%s:%s:Location Id TLV is not enabled\n",
			__func__, md->ifname);
		rc = 0;
		goto out_err;
	}

	/* location data size varies from type, query as string w/ max length */
	length = sizeof(struct tlv_info_locid) * 2 + 1;
	locstr = malloc(length);
	if (!locstr)
		goto out_err;

	memset(locstr, 0, length);
	if (get_config_tlvinfo_str(md->ifname, agent->type,
				   TLVID_MED(LLDP_MED_LOCATION_ID),
				   locstr, length)) {
		LLDPAD_DBG("%s:%s:Location Id TLV must be"
			" administratively configured\n",
			__func__, md->ifname);
		goto out_err;
	}

	/* calculate the size in binary */
	length = strlen(locstr) / 2;
	if (hexstr2bin(locstr, (u8 *)&locid, length)) {
		LLDPAD_DBG("%s:%s:Location Id TLV info corrupted: %s\n",
			__func__, md->ifname, locstr);
		goto out_err;
	}

	/* validate the loaded data */
	if (LLDP_MED_LOCID_FORMAT_INVALID(locid.format)) {
		LLDPAD_DBG("%s:%s:Location Id TLV info invalid: %s\n",
			__func__, md->ifname, locstr);
		goto out_err;
	}

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = length;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		goto out_err;
	}
	memcpy(tlv->info, &locid, tlv->length);
	md->locid = tlv;
	rc = 0;

out_err:
	if (locstr)
		free(locstr);
	return rc;
}

/*
 * med_get_netpoli - builds tlv_info_netploi struct
 * @md: the med data struct
 * @n: the tlv_info_netpoli data struct
 *
 * Returns 0 for success or error code for failure
 *
 * Either gets the netpoli from the config or build from scratch.
 *
 * TODO: currently only supports load from config, will fail if it's
 * not configured
 */
static int med_get_netpoli(struct med_data *md,
			   struct lldp_agent *agent,
			   struct tlv_info_netpoli *n)
{
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_NETWORK_POLICY)))
		return ENOENT;

	if (!get_config_tlvinfo_bin(md->ifname, agent->type,
				    TLVID_MED(LLDP_MED_NETWORK_POLICY),
				    n, sizeof(*n)))
		return 0;
	return EPERM;
}

/*
 * med_bld_netpoli_tlv - builds network policy tlv
 * @port: the port associated
 *
 * Returns 0 for success or error code for failure
 */
static int med_bld_netpoli_tlv(struct med_data *md,
			       struct lldp_agent *agent)
{
	int rc = EPERM;
	int devtype;
	struct tlv_info_netpoli netpoli;
	struct unpacked_tlv *tlv = NULL;

	/* free old one if it exists */
	FREE_UNPKD_TLV(md, netpoli);

	devtype = get_med_devtype(md->ifname, agent->type);
	switch (devtype) {
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		/* Only transmit if it is administratively configured */
		rc = med_get_netpoli(md, agent, &netpoli);
		if (rc == ENOENT)
			goto out_nobld;
		if (rc == EPERM) {
			LLDPAD_DBG("%s:%s: Must configure Network"
				" Policy TLV if it is enabled for Network"
				" Connectivity Devcie\n",
				__func__, md->ifname);
			goto out_err;
		}
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
		/* Optional: skip if failed to get it */
		if (med_get_netpoli(md, agent, &netpoli)) {
			LLDPAD_DBG("%s:%s: Skipping"
				" Network Policy TLV for Class I Device\n",
			 	__func__, md->ifname);
			goto out_nobld;
		}
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
		/* Mandatory */
		if (med_get_netpoli(md, agent, &netpoli)) {
			LLDPAD_DBG("%s:%s: Must enable and configure"
				" Network Policy TLV for Class II/III Device\n",
			 	__func__, md->ifname);
			goto out_err;
		}
		break;
	default:
		LLDPAD_DBG("%s:%s: unknown dev type %d:\n",
			__func__, md->ifname, devtype);
		goto out_err;
	}

	/* We should have a valid tlv_info_netpoli */
	if (netpoli.subtype != LLDP_MED_NETWORK_POLICY) {
		LLDPAD_DBG("%s:%s: Wrong subtype %d: should be %d\n",
			__func__, md->ifname, netpoli.subtype, LLDP_MED_NETWORK_POLICY);
		rc = EINVAL;
		goto out_err;
	}

	tlv = create_tlv();
	if (!tlv) {
		rc = ENOMEM;
		goto out_err;
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(netpoli);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		rc = ENOMEM;
		goto out_err;
	}
	memcpy(tlv->info, &netpoli, tlv->length);
	md->netpoli = tlv;

out_nobld:
	rc = 0;

out_err:
	return rc;
}

/*
 * med_bld_tlv - build all LLDP-MED TLVs
 * @md: the med data struct
 *
 * Returns 0 for success or error code for failure
 *
 */
static int med_bld_tlv(struct med_data *md,
		       struct lldp_agent *agent)
{
	int rc = EPERM;

	if (!port_find_by_name(md->ifname)) {
		rc = EEXIST;
		goto out_err;
	}

	/* no build if not enabled */
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_MED(LLDP_MED_RESERVED))) {
		LLDPAD_DBG("%s:%s:LLDP-MED is not enabled\n",
			__func__, md->ifname);
		rc = 0;
		goto out_err;
	}

	/* no build if enabled no devtype is given */
	if (!LLDP_MED_DEVTYPE_DEFINED(get_med_devtype(md->ifname, agent->type))) {
		LLDPAD_DBG("%s:%s:LLDP-MED devtype is not defined\n",
			__func__, md->ifname);
		goto out_err;
	}

	/* MED Cap is always mandatory for MED */
	if (med_bld_medcaps_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:MED Capabilities TLV is mandatory!\n",
			__func__, md->ifname);
		goto out_err;
	}

	/* MAC PHY TLV is mandatory for MED */
	if (!is_tlv_txenabled(md->ifname, agent->type,
			      TLVID_8023(LLDP_8023_MACPHY_CONFIG_STATUS))) {
		LLDPAD_DBG("%s:%s MAC PHY Config is mandatory for MED\n",
				__func__, md->ifname);
		rc = ENOTTY;
		goto out_err;
	}

	/* Build optional and conditional ones based on device type:
	 *
	 * LLDP-MED Endpoint Class I TLV Set: ANSI/TIA-1057-2006, 10.2.1.2
	 *	- Capabilities: mandatory
	 * 	- Network Policy: optional
	 * 	- Extended Power-via-MDI: mandatory only for 802.3af PD
	 * 	- Inventory: optional
	 * LLDP-MED Endpoint Class II TLV Set: ANSI/TIA-1057-2006, 10.2.1.3
	 *	- Capabilities: mandatory
	 * 	- Network Policy: mandatory
	 * 	- Extended Power-via-MDI: mandatory only for 802.3.af PD
	 * 	- Inventory: optional
	 * LLDP-MED Endpoint Class III TLV Set: ANSI/TIA-1057-2006, 10.2.1.4
	 *	- Capabilities: mandatory
	 * 	- Network Policy: mandatory
	 * 	- Location Identification: optional
	 * 	- Extended Power-via-MDI: mandatory only for 802.3.af PD
	 * 	- Inventory: optional
	 * LLDP-MED Network Connectivity TLV Set: ANSI/TIA-1057-2006,  10.2.1.1
	 *	- Capabilities: mandatory
	 * 	- Network Policy: exists only if administratively
	 *        configured
	 * 	- Location Identification: exists only if
	 *	  administratively configured
	 * 	- Extended Power-via-MDI: mandatory only for
	 *	  802.3.af PSE
	 * 	- Inventory: optional
	 *
	 */
	if (med_bld_netpoli_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:med_bld_netpoli_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (med_bld_locid_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:med_bld_locid_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (med_bld_powvmdi_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:med_bld_powvmdi_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	if (med_bld_inventory_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s:med_bld_inventory_tlv() failed\n",
				__func__, md->ifname);
		goto out_err;
	}
	rc = 0;

out_err:
	return rc;
}

/*
 * med_free_tlv - free allocated tlvs
 * @md: the private med data struct
 */
static void med_free_tlv(struct med_data *md)
{
	if (md) {
		FREE_UNPKD_TLV(md, medcaps);
		FREE_UNPKD_TLV(md, netpoli);
		FREE_UNPKD_TLV(md, locid);
		FREE_UNPKD_TLV(md, extpvm);
		FREE_UNPKD_TLV(md, inv_hwrev);
		FREE_UNPKD_TLV(md, inv_fwrev);
		FREE_UNPKD_TLV(md, inv_swrev);
		FREE_UNPKD_TLV(md, inv_serial);
		FREE_UNPKD_TLV(md, inv_manufacturer);
		FREE_UNPKD_TLV(md, inv_modelname);
		FREE_UNPKD_TLV(md, inv_assetid);
	}
}


static void med_free_data(struct med_user_data *mud)
{
	struct med_data *md;
	if (mud) {
		while (!LIST_EMPTY(&mud->head)) {
			md = LIST_FIRST(&mud->head);
			LIST_REMOVE(md, entry);
			med_free_tlv(md);
			free(md);
 		}
	}
}

struct packed_tlv *med_gettlv(struct port *port,
			      struct lldp_agent *agent)
{
	size_t size;
	struct med_data *md;
	struct packed_tlv *ptlv = NULL;

	md = med_data(port->ifname, agent->type);
	if (!md)
		goto out_err;

	med_free_tlv(md);
	if (med_bld_tlv(md, agent)) {
		goto out_err;
	}

	size = TLVSIZE(md->medcaps)
		+ TLVSIZE(md->netpoli)
		+ TLVSIZE(md->locid)
		+ TLVSIZE(md->extpvm)
		+ TLVSIZE(md->inv_hwrev)
		+ TLVSIZE(md->inv_fwrev)
		+ TLVSIZE(md->inv_swrev)
		+ TLVSIZE(md->inv_serial)
		+ TLVSIZE(md->inv_manufacturer)
		+ TLVSIZE(md->inv_modelname)
		+ TLVSIZE(md->inv_assetid);

	if (!size)
		goto out_err;

	ptlv = create_ptlv();
	if (!ptlv)
		goto out_err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	/* Pack all previously-built tlvs, any failure in packing fails all */
	ptlv->size = 0;
	PACK_TLV_AFTER(md->medcaps, ptlv, size, out_free);
	PACK_TLV_AFTER(md->netpoli, ptlv, size, out_free);
	PACK_TLV_AFTER(md->locid, ptlv, size, out_free);
	PACK_TLV_AFTER(md->extpvm, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_hwrev, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_fwrev, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_swrev, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_serial, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_manufacturer, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_modelname, ptlv, size, out_free);
	PACK_TLV_AFTER(md->inv_assetid, ptlv, size, out_free);
	return ptlv;
out_free:
	free_pkd_tlv(ptlv);
out_err:
	LLDPAD_DBG("%s:%s: failed\n", __func__, port->ifname);
	return NULL;
}

void med_ifdown(char *ifname, struct lldp_agent *agent)
{
	struct med_data *md;

	md = med_data(ifname, agent->type);
	if (!md)
		goto out_err;

	LIST_REMOVE(md, entry);
	med_free_tlv(md);
	free(md);
	LLDPAD_INFO("%s:port %s removed\n", __func__, ifname);
	return;
out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname);
	return;
}

void med_ifup(char *ifname, struct lldp_agent *agent)
{
	struct med_data *md;
	struct med_user_data *mud;

	md = med_data(ifname, agent->type);
	if (md) {
		LLDPAD_DBG("%s:%s exists\n", __func__, ifname);
		goto out_err;
	}

	/* not found, alloc/init per-port tlv data */
	md = (struct med_data *) malloc(sizeof(*md));
	if (!md) {
		LLDPAD_DBG("%s:%s malloc %zu failed\n",
			__func__, ifname, sizeof(*md));
		goto out_err;
	}
	memset(md, 0, sizeof(struct med_data));
	strncpy(md->ifname, ifname, IFNAMSIZ);
	md->agenttype = agent->type;

	if (med_bld_tlv(md, agent)) {
		LLDPAD_DBG("%s:%s med_bld_tlv failed\n",
			__func__, ifname);
		free(md);
		goto out_err;
	}
	mud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_MED);
	LIST_INSERT_HEAD(&mud->head, md, entry);
	LLDPAD_INFO("%s:port %s added\n", __func__, ifname);
	return;

out_err:
	LLDPAD_INFO("%s:port %s adding failed\n", __func__, ifname);
	return;
}

struct lldp_module *med_register(void)
{
	struct lldp_module *mod;
	struct med_user_data *mud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("failed to malloc LLDP-MED module data\n");
		goto out_err;
	}
	mud = malloc(sizeof(struct med_user_data));
	if (!mud) {
		free(mod);
		LLDPAD_ERR("failed to malloc LLDP-MED module user data\n");
		goto out_err;
	}
	LIST_INIT(&mud->head);
 	mod->id = LLDP_MOD_MED;
	mod->ops = &med_ops;
	mod->data = mud;

	LLDPAD_INFO("%s:done\n", __func__);
	return mod;

out_err:
	LLDPAD_INFO("%s:failed\n", __func__);
	return NULL;

}

void med_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		med_free_data((struct med_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_INFO("%s:done\n", __func__);
}
