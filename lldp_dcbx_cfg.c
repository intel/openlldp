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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "lldp_dcbx_cfg.h"
#include "dcb_protocol.h"
#include "messages.h"
#include "lldpad.h"
#include "config.h"
#include "libconfig.h"
#include "lldp_util.h"
#include "dcb_driver_interface.h"

#define CFG_VERSION "1.0"

extern config_t lldpad_cfg;

static void
config_setting_add_app_default(config_setting_t *eth_setting, int subtype)
{
	config_setting_t *tmp_setting = NULL;
	config_setting_t *tmp2_setting = NULL;
	char abuf[32];

	sprintf(abuf, "app_%d", subtype);

	tmp_setting = config_setting_add(eth_setting, abuf,
		CONFIG_TYPE_GROUP);
	if (!tmp_setting)
		goto error;

	tmp2_setting = config_setting_add(tmp_setting, "app_enable",
		CONFIG_TYPE_INT);
	if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 1))
		goto error;
	tmp2_setting = config_setting_add(tmp_setting, "app_advertise",
		CONFIG_TYPE_INT);
	if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 1))
		goto error;
	tmp2_setting = config_setting_add(tmp_setting, "app_willing",
		CONFIG_TYPE_INT);
	if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 1))
		goto error;

	tmp2_setting = config_setting_add(tmp_setting, "app_cfg",
		CONFIG_TYPE_STRING);
	if (!tmp2_setting)
		goto error;

	if (subtype == APP_FCOE_STYPE)
		snprintf(abuf, sizeof(abuf), "%02x", APP_FCOE_DEFAULT_DATA);
	else if (subtype == APP_ISCSI_STYPE)
		snprintf(abuf, sizeof(abuf), "%02x", APP_ISCSI_DEFAULT_DATA);
	else if (subtype == APP_FIP_STYPE)
		snprintf(abuf, sizeof(abuf), "%02x", APP_FIP_DEFAULT_DATA);
	else
		snprintf(abuf, sizeof(abuf), "%02x", 0x03);

	if (!config_setting_set_string(tmp2_setting, abuf))
		goto error;

	/* Success */
	return;
error:
	LLDPAD_DBG("Failed setting defaults for app subtype %d", subtype);
}

static config_setting_t *construct_new_setting(char *device_name)
{
	config_setting_t *dcbx_setting = NULL;
	config_setting_t *eth_setting = NULL;
	config_setting_t *tmp_setting = NULL;
	config_setting_t *tmp2_setting = NULL;
	char abuf[32];
	int i;

	dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	if (!dcbx_setting)
		return NULL;

	eth_setting = config_setting_add(dcbx_setting, device_name,
		CONFIG_TYPE_GROUP);
	if (!eth_setting)
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "dcb_enable",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pfc_enable",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pfc_advertise",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pfc_willing",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pfc_admin_mode",
		CONFIG_TYPE_ARRAY);
	if (!tmp_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp_setting, -1, 0))
			goto set_error;
	}

	tmp_setting = config_setting_add(eth_setting, "pg_enable",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pg_advertise",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pg_willing",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, 1))
		goto set_error;

	tmp_setting = config_setting_add(eth_setting, "pg_tx_bwg_alloc",
		CONFIG_TYPE_ARRAY);
	if (!tmp_setting)
		goto set_error;
	for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
		if (!config_setting_set_int_elem(tmp_setting, -1, 0))
			goto set_error;
	}

	tmp_setting = config_setting_add(eth_setting,
		"pg_tx_traffic_attribs_type", CONFIG_TYPE_GROUP);
	if (!tmp_setting)
		goto set_error;

	tmp2_setting = config_setting_add(tmp_setting, "traffic_class_mapping",
		CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, i))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting,
		"bandwidth_group_mapping", CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, 0))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting,
		"percent_of_bandwidth_group", CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, 0))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting, "strict_priority",
		CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, 0))
			goto set_error;
	}

	tmp_setting = config_setting_add(eth_setting, "pg_rx_bwg_alloc",
		CONFIG_TYPE_ARRAY);
	if (!tmp_setting)
		goto set_error;
	for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
		if (!config_setting_set_int_elem(tmp_setting, -1, 0))
			goto set_error;
	}

	tmp_setting = config_setting_add(eth_setting,
		"pg_rx_traffic_attribs_type", CONFIG_TYPE_GROUP);
	if (!tmp_setting)
		goto set_error;

	tmp2_setting = config_setting_add(tmp_setting, "traffic_class_mapping",
		CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, i))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting,
		"bandwidth_group_mapping", CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, i))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting,
		"percent_of_bandwidth_group", CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, i))
			goto set_error;
	}

	tmp2_setting = config_setting_add(tmp_setting, "strict_priority",
		CONFIG_TYPE_ARRAY);
	if (!tmp2_setting)
		goto set_error;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (!config_setting_set_int_elem(tmp2_setting, -1, i))
			goto set_error;
	}

	tmp_setting = config_setting_add(eth_setting, "bwg_description",
		CONFIG_TYPE_ARRAY);
	if (!tmp_setting)
		goto set_error;
	for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
		if (!config_setting_set_string_elem(tmp_setting, -1, ""))
			goto set_error;
	}

	for (i = 0; i < DCB_MAX_APPTLV; i++)
		config_setting_add_app_default(eth_setting, i);
	
	for (i = 0; i < DCB_MAX_LLKTLV; i++) {
		sprintf(abuf, "llink_%d", i);

		tmp_setting = config_setting_add(eth_setting, abuf,
			CONFIG_TYPE_GROUP);
		if (!tmp_setting)
			goto set_error;

		tmp2_setting = config_setting_add(tmp_setting, "llink_enable",
			CONFIG_TYPE_INT);
		if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 0))
			goto set_error;

		tmp2_setting = config_setting_add(tmp_setting,
			"llink_advertise", CONFIG_TYPE_INT);
		if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 0))
			goto set_error;

		tmp2_setting = config_setting_add(tmp_setting, "llink_willing",
			CONFIG_TYPE_INT);
		if (!tmp2_setting || !config_setting_set_int(tmp2_setting, 0))
			goto set_error;
	}

	return eth_setting;

set_error:
	LLDPAD_DBG("Failed constructing new settings for config file %s",
		    cfg_file_name);
	return NULL;
}

int dcbx_default_cfg_file(void)
{
	config_setting_t *root_setting = NULL;
	config_setting_t *dcbx_setting = NULL;
	config_setting_t *tmp_setting = NULL;

	/* add the legacy default dcbx configuration settings */
        root_setting = config_root_setting(&lldpad_cfg);
	dcbx_setting = config_setting_add(root_setting, DCBX_SETTING,
		CONFIG_TYPE_GROUP);

	/* dcbx configuration exists abort creating cfg */
	if (!dcbx_setting) 
		return 0;

	tmp_setting = config_setting_add(dcbx_setting, "version",
		CONFIG_TYPE_STRING);
	if (!tmp_setting ||
	    !config_setting_set_string(tmp_setting, CFG_VERSION))
		goto error;

	tmp_setting = config_setting_add(dcbx_setting, "dcbx_version",
		CONFIG_TYPE_INT);
	if (!tmp_setting || !config_setting_set_int(tmp_setting, dcbx_subtype2))
		goto error;

	config_write_file(&lldpad_cfg, cfg_file_name);

	return 0;
error:
	LLDPAD_DBG("Failed to generate default config file %s", cfg_file_name);
	return 1;
}

void cfg_fixup(config_setting_t *eth_settings)
{
	config_setting_t *setting = NULL;
	char abuf[2*DCB_MAX_TLV_LENGTH + 1];
	int i;

	setting = config_setting_get_member(eth_settings, "app_0");
	/*
	 *  If there's no APP 0 entry then there's no need to create any others
	 */
	if (!setting)
		return;

	for (i = 1; i < DCB_MAX_APPTLV; i++) {
		sprintf(abuf, "app_%d", i);
		setting = config_setting_get_member(eth_settings, abuf);
		/*
		 *  Entry exists, go to the next one
		 */
		if (setting)
			continue;
		config_setting_add_app_default(eth_settings, i);
	}

	return;
}

static int _set_persistent(char *device_name, int dcb_enable,
		pg_attribs *pg, pfc_attribs *pfc, pg_info *bwg,
		app_attribs *app, u8 app_subtype,
		llink_attribs *llink, u8 link_subtype)
{
	full_dcb_attribs attribs;
	config_setting_t *dcbx_setting = NULL;
	config_setting_t *eth_settings = NULL;
	config_setting_t *setting = NULL;
	config_setting_t *setting_traffic = NULL;
	config_setting_t *setting_value = NULL;
	char abuf[2*DCB_MAX_TLV_LENGTH + 1];
	int result, i;

	dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	if (dcbx_setting)
		eth_settings = config_setting_get_member(dcbx_setting,
							 device_name);

	/* init the internal data store for device_name */
	if (NULL == eth_settings) {

		result = cmd_success;
		if (result == cmd_success && pg == NULL) {
			result = get_pg(device_name, &attribs.pg);
			pg = &attribs.pg;
		}
		if (result == cmd_success && pfc == NULL) {
			result = get_pfc(device_name, &attribs.pfc);
			pfc = &attribs.pfc;
		}
		if (result == cmd_success && app == NULL) {
			result = get_app(device_name,app_subtype,&attribs.app[app_subtype]);
			app = &attribs.app[app_subtype];
		}
		if (result == cmd_success && llink == NULL) {
			result = get_llink(device_name,0,&attribs.llink[0]);
			llink = &attribs.llink[0];
		}
		if (result != cmd_success)
			goto set_error;

		eth_settings = construct_new_setting(device_name);
		if (!eth_settings)
			goto set_error;
	}

	setting = config_setting_get_member(eth_settings, "dcb_enable");
	if (!setting || !config_setting_set_int(setting, dcb_enable))
		goto set_error;

	if (NULL != pfc) {
		setting = config_setting_get_member(eth_settings, "pfc_enable");
		if (!setting ||
			!config_setting_set_int(setting, pfc->protocol.Enable))
			goto set_error;

		setting = config_setting_get_member(eth_settings,
			"pfc_advertise");
		if (!setting || !config_setting_set_int(setting,
				pfc->protocol.Advertise))
			goto set_error;

		setting = config_setting_get_member(eth_settings,
			"pfc_willing");
		if (!setting || !config_setting_set_int(setting,
			pfc->protocol.Willing))
			goto set_error;

		setting = config_setting_get_member(eth_settings,
			"pfc_admin_mode");
		if (!setting) {
			goto set_error;
		} else {
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i)) {
					goto set_error;
				}
				if (!config_setting_set_int_elem(setting, i,
					pfc->admin[i])) {
					goto set_error;
				}
			}
		}
	}

	/* Read PG setting */
	if (NULL != pg) {
		setting = config_setting_get_member(eth_settings, "pg_enable");
		if (!setting || !config_setting_set_int(setting,
			pg->protocol.Enable))
			goto set_error;

		setting = config_setting_get_member(eth_settings,
			"pg_advertise");
		if (!setting  || !config_setting_set_int(setting,
			pg->protocol.Advertise))
			goto set_error;

		setting = config_setting_get_member(eth_settings, "pg_willing");
		if (!setting || !config_setting_set_int(setting,
			pg->protocol.Willing))
			goto set_error;

		setting = config_setting_get_member(eth_settings,
			"pg_tx_bwg_alloc");
		if (!setting) {
			goto set_error;
		} else {
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->tx.pg_percent[i]))
					goto set_error;
			}
		}

		setting_traffic = config_setting_get_member(eth_settings,
			"pg_tx_traffic_attribs_type");
		if (!setting_traffic) {
			goto set_error;
		} else {
			setting = config_setting_get_member(setting_traffic,
				"traffic_class_mapping");
			if (!setting)
				goto set_error;
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->tx.up[i].pgid))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"bandwidth_group_mapping");
			if (!setting)
				goto set_error;
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->tx.up[i].bwgid))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"percent_of_bandwidth_group");
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
				   pg->tx.up[i].percent_of_pg_cap))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"strict_priority");
			if (!setting)
				goto set_error;
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->tx.up[i].strict_priority))
					goto set_error;
			}
		}

		/* rx */
		setting = config_setting_get_member(eth_settings,
			"pg_rx_bwg_alloc");
		if (!setting) {
			goto set_error;
		} else {
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->rx.pg_percent[i]))
					goto set_error;
			}
		}

		setting_traffic = config_setting_get_member(eth_settings,
			"pg_rx_traffic_attribs_type");
		if (!setting_traffic) {
			goto set_error;
		} else {
			setting = config_setting_get_member(setting_traffic,
				"traffic_class_mapping");
			if (!setting)
				goto set_error;
			for (i = 0; i<config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->rx.up[i].pgid))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"bandwidth_group_mapping");
			if (!setting)
				goto set_error;
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->rx.up[i].bwgid))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"percent_of_bandwidth_group");
			if (!setting)
				goto set_error;
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
				   pg->rx.up[i].percent_of_pg_cap))
					goto set_error;
			}

			setting = config_setting_get_member(setting_traffic,
				"strict_priority");
			if (!setting)
				goto set_error;
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_int_elem(setting, i,
					pg->rx.up[i].strict_priority))
					goto set_error;
			}
		}
	}

	if (NULL != bwg) {
		setting = config_setting_get_member(eth_settings,
			"bwg_description");
		if (!setting) {
			goto set_error;
		} else {
			for (i = 0; i < config_setting_length(setting); i++) {
				if (!config_setting_get_elem(setting, i))
					goto set_error;
				if (!config_setting_set_string_elem(setting, i,
					bwg->pgid_desc[i]))
					goto set_error;
			}
		}
	}

	/* Update APP settings */
	if (NULL != app) {
		sprintf(abuf, "app_%d", app_subtype);

		setting = config_setting_get_member(eth_settings, abuf);

		if (!setting) {
			/*
			 *  If we have an old version of the config file there
			 *    will only be a zero'th app entry, fixup the
			 *    config file to have all the other app entries.
			 */
			cfg_fixup(eth_settings);
			setting = config_setting_get_member(eth_settings, abuf);
			if (!setting)
				goto set_error;
		}
 
		setting_value = config_setting_get_member(setting,
			"app_enable");

		if (!setting_value || !config_setting_set_int(setting_value,
			app->protocol.Enable))
			goto set_error;

		setting_value = config_setting_get_member(setting,
			"app_advertise");
		if (!setting_value || !config_setting_set_int(setting_value,
			app->protocol.Advertise))
			goto set_error;

		setting_value = config_setting_get_member(setting,
			"app_willing");
		if (!setting_value || !config_setting_set_int(setting_value,
			app->protocol.Willing))
			goto set_error;

		memset(abuf, 0, sizeof(abuf));
		setting_value = config_setting_get_member(setting, "app_cfg");
		if (setting_value) {
			for (i = 0; i < (int)app->Length; i++)
				sprintf(abuf+2*i, "%02x", app->AppData[i]);
			if (!config_setting_set_string(setting_value, abuf))
				goto set_error;
		} else {
			goto set_error;
		}
	}

	/* Update Logical link settings */
	if (NULL != llink) {
		sprintf(abuf, "llink_%d", link_subtype);

		setting = config_setting_get_member(eth_settings, abuf);

		if (!setting)
			goto set_error;

		setting_value = config_setting_get_member(setting,
			"llink_enable");

		if (!setting_value || !config_setting_set_int(setting_value,
			llink->protocol.Enable))
			goto set_error;

		setting_value = config_setting_get_member(setting,
			"llink_advertise");
		if (!setting_value || !config_setting_set_int(setting_value,
			llink->protocol.Advertise))
			goto set_error;

		setting_value = config_setting_get_member(setting,
			"llink_willing");
		if (!setting_value || !config_setting_set_int(setting_value,
			llink->protocol.Willing))
			goto set_error;
	}


	config_write_file(&lldpad_cfg, cfg_file_name);

	return 0;

set_error:
	LLDPAD_ERR("update of config file %s failed for %s",
		   cfg_file_name, device_name);
	return cmd_failed;
}

static int get_default_persistent(const char *ifname, full_dcb_attribs *attribs)
{
	int i;

	if (get_pg(DEF_CFG_STORE, &attribs->pg) != cmd_success)
		return 1;

	if (get_pfc(DEF_CFG_STORE, &attribs->pfc) != cmd_success)
		return 1;

	get_dcb_numtcs(ifname, &attribs->pg.num_tcs, &attribs->pfc.num_tcs);

	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		if (get_app(DEF_CFG_STORE, i, &attribs->app[i]) != cmd_success)
			return 1;
	}

	for (i = 0; i < DCB_MAX_LLKTLV; i++) {
		if (get_llink(DEF_CFG_STORE, i,
			&attribs->llink[i]) != cmd_success)
			return 1;
	}

	return 0;
}

int save_dcb_enable_state(char *device_name, int dcb_enable)
{
	return _set_persistent(device_name, dcb_enable, NULL, NULL, NULL, NULL, 
				0, NULL, 0);
}

int save_dcbx_version(int dcbx_version)
{
	config_setting_t *dcbx_setting;
	config_setting_t *setting;

	dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	if (!dcbx_setting)
		return 1;

	setting = config_setting_get_member(dcbx_setting, "dcbx_version");
	if (!setting || !config_setting_set_int(setting, dcbx_version) ||
		!config_write_file(&lldpad_cfg, cfg_file_name))
		return 1;

	return 0;
}

int set_persistent(char *device_name, full_dcb_attrib_ptrs *attribs)
{
	int enabled = 0;
	int not_present = get_dcb_enable_state(device_name, &enabled);

	/* When the 'dcb_enable' config param does not exist put DCBX
	 * into DEFAULT mode. This will cause DCBX to be enabled when
	 * a DCBX TLV is received
	 */
	if (not_present)
		enabled = LLDP_DCBX_DEFAULT;

	return _set_persistent(device_name, enabled, attribs->pg, attribs->pfc,
			attribs->pgid, attribs->app, attribs->app_subtype, 
			attribs->llink, LLINK_FCOE_STYPE);
}


int get_persistent(char *device_name, full_dcb_attribs *attribs)
{
	config_setting_t *dcbx_setting = NULL;
	config_setting_t *eth_settings = NULL;
	config_setting_t *setting = NULL;
	config_setting_t *setting_array = NULL;
	config_setting_t *setting_traffic = NULL;
	config_setting_t *setting_value = NULL;
	full_dcb_attrib_ptrs attrib_ptrs = {0, 0, 0, 0, 0, 0, 0};
	int result = cmd_failed, i;
	int results[MAX_USER_PRIORITIES];
	int len;
	char abuf[32];

	memset(attribs, 0, sizeof(*attribs));
	dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	if (dcbx_setting)
		eth_settings = config_setting_get_member(dcbx_setting,
							 device_name);

	/* init the internal data store for device_name */
	result = get_default_persistent(device_name, attribs);
	if (NULL == eth_settings) {
		assert(memcmp(device_name, DEF_CFG_STORE, 
			strlen(DEF_CFG_STORE)));

		return result;
	}

	/* Read pfc setting */
	if (get_int_config(eth_settings, "pfc_enable", TYPE_BOOL,
		&result))
		attribs->pfc.protocol.Enable = result;
	else
		goto set_default;

	if (get_int_config(eth_settings, "pfc_advertise", TYPE_BOOL,
		&result))
		attribs->pfc.protocol.Advertise = result;
	else
		goto set_default;

	if (get_int_config(eth_settings, "pfc_willing", TYPE_BOOL,
		&result))
		attribs->pfc.protocol.Willing = result;
	else
		goto set_default;

	if (!get_array_config(eth_settings, "pfc_admin_mode", TYPE_BOOL,
		(int *)&attribs->pfc.admin[0]))
		goto set_default;

	/* read PG protocol settings */
	if (get_int_config(eth_settings, "pg_enable", TYPE_BOOL,
		&result))
		attribs->pg.protocol.Enable = result;
	else
		goto set_default;

	if (get_int_config(eth_settings, "pg_advertise", TYPE_BOOL,
		&result))
		attribs->pg.protocol.Advertise = result;
	else
		goto set_default;

	if (get_int_config(eth_settings, "pg_willing", TYPE_BOOL,
		&result))
		attribs->pg.protocol.Willing = result;
	else
		goto set_default;

	/* read PG TX settings */
	memset(results, 0, sizeof(results));
	if (get_array_config(eth_settings, "pg_tx_bwg_alloc", TYPE_PERCENT,
		&results[0]))
		for (i = 0; i < MAX_USER_PRIORITIES; i++)
			attribs->pg.tx.pg_percent[i] = results[i];
	else
		goto set_default;

	setting_traffic = config_setting_get_member(eth_settings,
		"pg_tx_traffic_attribs_type");

	if (!setting_traffic) {
		goto set_default;
	} else {
		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "traffic_class_mapping",
			TYPE_CHAR, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.tx.up[i].pgid =
					results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "bandwidth_group_mapping",
			TYPE_CHAR, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.tx.up[i].bwgid =
					results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic,
			"percent_of_bandwidth_group", TYPE_PERCENT,
			&results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
			    attribs->pg.tx.up[i].percent_of_pg_cap
				= results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "strict_priority",
			TYPE_PRIORITY, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.tx.up[i].strict_priority =
					results[i];
		else
			goto set_default;
	}

	/* read PG RX settings */
	memset(results, 0, sizeof(results));
	if (get_array_config(eth_settings, "pg_rx_bwg_alloc", TYPE_PERCENT,
		&results[0]))
		for (i = 0; i < MAX_USER_PRIORITIES; i++)
			attribs->pg.rx.pg_percent[i] = results[i];
	else
		goto set_default;

	setting_traffic = config_setting_get_member(eth_settings,
		"pg_rx_traffic_attribs_type");

	if (!setting_traffic) {
		goto set_default;
	} else {
		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "traffic_class_mapping",
			TYPE_CHAR, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.rx.up[i].pgid =
					results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "bandwidth_group_mapping",
			TYPE_CHAR, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.rx.up[i].bwgid =
					results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic,
			"percent_of_bandwidth_group", TYPE_PERCENT,
			&results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
			    attribs->pg.rx.up[i].percent_of_pg_cap
				= results[i];
		else
			goto set_default;

		memset(results, 0, sizeof(results));
		if (get_array_config(setting_traffic, "strict_priority",
			TYPE_PRIORITY, &results[0]))
			for (i = 0; i < MAX_USER_PRIORITIES; i++)
				attribs->pg.rx.up[i].strict_priority =
					results[i];
		else
			goto set_default;
	}

	setting = config_setting_get_member(eth_settings, "bwg_description");
	if (setting) {
		for (i = 0; i < config_setting_length(setting); i++) {
			setting_array = config_setting_get_elem(setting, i);
			const char *bwg_descp =
				config_setting_get_string(setting_array);
			if (bwg_descp)
				strncpy(attribs->descript.pgid_desc[i],
					bwg_descp, MAX_DESCRIPTION_LEN-1);
		}

		/*The counter starts from 1, not 0 */
		attribs->descript.max_pgid_desc = i;
	}

	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		sprintf(abuf, "app_%d", i);

		setting = config_setting_get_member(eth_settings, abuf);

		if (!setting) {
			/*
			 *  If we have an old config file there will be the
			 *    zero'th entry so use it as the EWA template for
			 *    all other application types.  Other data values
			 *    we be the default value.
			 */
			attribs->app[i].protocol.Enable = attribs->app[0].protocol.Enable;
			attribs->app[i].protocol.Willing = attribs->app[0].protocol.Willing;
 			continue;
		}

		/* Read app setting */
		if (get_int_config(setting, "app_enable", TYPE_BOOL,
			&result))
			attribs->app[i].protocol.Enable = result;
		else
			goto set_default;

		if (get_int_config(setting, "app_advertise", TYPE_BOOL,
			&result))
			attribs->app[i].protocol.Advertise = result;
		else
			goto set_default;

		if (get_int_config(setting, "app_willing", TYPE_BOOL,
			&result))
			attribs->app[i].protocol.Willing = result;
		else
			goto set_default;

		setting_value = config_setting_get_member(setting, "app_cfg");
		if (setting_value) {
			const char *app_cfg_hex =
				config_setting_get_string(setting_value);
			len = strlen(app_cfg_hex);
			if (len % 2 || len > DCB_MAX_TLV_LENGTH) {
				LLDPAD_DBG("invalid length for app_cfg");
				goto set_default;
			}

			if (hexstr2bin(app_cfg_hex, attribs->app[i].AppData,
				len/2)) {
				LLDPAD_DBG("invalid value for app_cfg");
				goto set_default;
			}
			attribs->app[i].Length = len/2;
		}
	}

	for (i = 0; i < DCB_MAX_LLKTLV; i++) {
		sprintf(abuf, "llink_%d", i);

		setting = config_setting_get_member(eth_settings, abuf);
		if (!setting)
			continue;

		/* Read app setting */
		if (get_int_config(setting, "llink_enable", TYPE_BOOL,
			&result))
			attribs->llink[i].protocol.Enable = result;
		else
			goto set_default;

		if (get_int_config(setting, "llink_advertise", TYPE_BOOL,
			&result))
			attribs->llink[i].protocol.Advertise = result;
		else
			goto set_default;

		if (get_int_config(setting, "llink_willing", TYPE_BOOL,
			&result))
			attribs->llink[i].protocol.Willing = result;
		else
			goto set_default;
	}

	return 0;

set_default:
	LLDPAD_DBG("Error read config file.\n");
	result = get_default_persistent(device_name, attribs);

	if (!result) {
		attrib_ptrs.pg = &attribs->pg;
		attrib_ptrs.pfc = &attribs->pfc;
		result = dcb_check_config(&attrib_ptrs);
	}

	return result;
}

/*
 * get_dcb_enable_state - check config for dcb_enable
 * @ifname: the port name
 * @result: output value buffer as int
 * 
 * Supports old and new config format
 */
int get_dcb_enable_state(char *ifname, int *result)
{
	int rc = EINVAL;
	config_setting_t *settings = NULL;
	char path[sizeof(DCBX_SETTING) + IFNAMSIZ + 16];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s.%s.dcb_enable", DCBX_SETTING, ifname);
	settings = config_lookup(&lldpad_cfg, path);
	if (!settings) {
		LLDPAD_INFO("### %s:%s:failed on %s\n", __func__, ifname, path);
		snprintf(path, sizeof(path), "%s.dcb_enable", ifname);
		settings = config_lookup(&lldpad_cfg, path);
		if (!settings) {
			LLDPAD_INFO("### %s:%s:failed again %s\n", __func__, ifname, path);
			rc = EIO;
			goto out_err;
		}
	}
	*result = (int)config_setting_get_int(settings);
	rc = 0;
out_err:
	return rc;
}

int get_dcbx_version(int *result)
{
	config_setting_t *dcbx_setting = NULL;
	int rval = 0;

	dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	if (!dcbx_setting) {
		create_default_cfg_file();
		dcbx_setting = config_lookup(&lldpad_cfg, DCBX_SETTING);
	}

	if (get_int_config(dcbx_setting, "dcbx_version", TYPE_INT, result)) {
		switch (*result) {
		case dcbx_subtype1:
		case dcbx_subtype2:
		case dcbx_force_subtype1:
		case dcbx_force_subtype2:
			rval = 1;
			break;
		default:
			break;
		}
	}

	return rval;
}

