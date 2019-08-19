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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "lldp.h"
#include "lldp_evb.h"
#include "qbg_vdp.h"
#include "lldp_tlv.h"
#include "lldp_mand_clif.h"
#include "config.h"
#include "clif_msgs.h"
#include "messages.h"

#define EVB_BUF_SIZE			256
#define ARG_EVB_FORWARDING_MODE		"fmode"
#define VAL_EVB_FMODE_BRIDGE		"bridge"
#define VAL_EVB_FMODE_REFLECTIVE_RELAY	"reflectiverelay"
#define ARG_EVB_CAPABILITIES		"capabilities"
#define VAL_EVB_CAPA_RTE		"rte"
#define VAL_EVB_CAPA_ECP		"ecp"
#define VAL_EVB_CAPA_VDP		"vdp"
#define VAL_EVB_CAPA_NONE		"none"
#define ARG_EVB_VSIS			"vsis"
#define ARG_EVB_RTE			"rte"

/*
 * Read EVB specific data from the configuration file.
 */
static const char *evb_conf_string(char *ifname, enum agent_type type,
				   char *ext, int def)
{
	char arg_path[EVB_BUF_SIZE];
	const char *param = NULL;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, TLVID_8021Qbg(LLDP_EVB_SUBTYPE), ext);

	if (get_cfg(ifname, type, arg_path, &param, CONFIG_TYPE_STRING)) {
		LLDPAD_INFO("%s:%s agent %d loading EVB policy for %s"
			    " failed, using default (%d)\n", __func__,
			    ifname, type, ext, def);
		return 0;
	}
	return param;
}

/*
 * Read forwarding mode from configuration file.
 */
u8 evb_conf_fmode(char *ifname, enum agent_type type)
{
	u8 smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;
	const char *value;

	value = evb_conf_string(ifname, type, ARG_EVB_FORWARDING_MODE, smode);
	if (value) {
		if (strcasestr(value, VAL_EVB_FMODE_BRIDGE))
			smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;
		if (strcasestr(value, VAL_EVB_FMODE_REFLECTIVE_RELAY))
			smode = LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
		LLDPAD_DBG("%s:%s agent %d policy %s %s(%#x)\n", __func__,
			   ifname, type, ARG_EVB_FORWARDING_MODE, value, smode);
	}
	return smode;
}

/*
 * Read maximum number of VSIs from configuration file.
 */
u16 evb_conf_vsis(char *ifname, enum agent_type type)
{
	u16 svsi = LLDP_EVB_DEFAULT_SVSI;
	const char *value;

	value = evb_conf_string(ifname, type, ARG_EVB_VSIS, svsi);
	if (value) {
		svsi = atoi(value);
		LLDPAD_DBG("%s:%s agent %d policy %s %s(%#x)\n", __func__,
			   ifname, type, ARG_EVB_VSIS, value, svsi);
	}
	return svsi;
}

/*
 * Read capabilities from configuration file.
 */
u8 evb_conf_capa(char *ifname, enum agent_type type)
{
	u8 scap = 0;
	const char *value;

	value = evb_conf_string(ifname, type, ARG_EVB_CAPABILITIES, scap);
	if (value) {
		if (strcasestr(value, VAL_EVB_CAPA_RTE))
			scap = LLDP_EVB_CAPABILITY_PROTOCOL_RTE;

		if (strcasestr(value, VAL_EVB_CAPA_ECP))
			scap |= LLDP_EVB_CAPABILITY_PROTOCOL_ECP;

		if (strcasestr(value, VAL_EVB_CAPA_VDP))
			scap |= LLDP_EVB_CAPABILITY_PROTOCOL_VDP;

		if (strcasestr(value, VAL_EVB_CAPA_NONE))
			scap = 0;

		LLDPAD_DBG("%s:%s agent %d policy %s %s(%#x)\n",
			   __func__, ifname, type, ARG_EVB_CAPABILITIES, value,
			   scap);
	}
	return scap;
}

/*
 * Read RTE value from configuration file.
 */
u8 evb_conf_rte(char *ifname, enum agent_type type)
{
	u8 rte = LLDP_EVB_DEFAULT_RTE;
	const char *value;

	value = evb_conf_string(ifname, type, ARG_EVB_RTE, rte);
	if (value) {
		rte = atoi(value);
		LLDPAD_DBG("%s:%s agent %d policy %s %s(%#x)\n", __func__,
			   ifname, type, ARG_EVB_RTE, value, rte);
	}
	return rte;
}

/*
 * Read transmit status from configuration file.
 */
int evb_conf_enabletx(char *ifname, enum agent_type type)
{
	return is_tlv_txenabled(ifname, type, TLVID_8021Qbg(LLDP_EVB_SUBTYPE));
}

static int evb_cmdok(struct cmd *cmd, int expected)
{
	if (cmd->cmd != expected)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case TLVID_8021Qbg(LLDP_EVB_SUBTYPE):
		if (cmd->type != NEAREST_CUSTOMER_BRIDGE)
			return cmd_agent_not_supported;

		return cmd_success;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}
}

static int
get_arg_tlvtxenable(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		    char *obuf, int obuf_len)
{
	cmd_status good_cmd = evb_cmdok(cmd, cmd_gettlv);
	char *s, arg_path[EVB_BUF_SIZE];
	int value;

	if (good_cmd != cmd_success)
		return good_cmd;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);
	if (get_cfg(cmd->ifname, cmd->type, arg_path, &value, CONFIG_TYPE_BOOL))
		value = false;

	if (value)
		s = VAL_YES;
	else
		s = VAL_NO;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);

	return cmd_success;
}

static int _set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
				bool test)
{
	int value;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	if (!strcasecmp(argvalue, VAL_YES))
		value = 1;
	else if (!strcasecmp(argvalue, VAL_NO))
		value = 0;
	else
		return cmd_bad_params;

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (ed) {
		if (vdp_vsis(ed->ifname))
			return cmd_failed;
	}

	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL)){
		LLDPAD_ERR("%s: error saving EVB enabletx (%s)\n", cmd->ifname,
			   argvalue);
		return cmd_failed;
	}
	if (ed)
		ed->txmit = value;

	LLDPAD_INFO("%s: changed EVB enabletx (%s)\n", cmd->ifname, argvalue);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_tlvtxenable(cmd, arg, argvalue, false);
}

static int test_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	/*
	 * Make sure either evb draft 0.2 or evb ratified standard is
	 * running at the same time but not both.
	 */
	if (!strcasecmp(argvalue, VAL_YES)
	    && is_tlv_txenabled(cmd->ifname, cmd->type,
				TLVID(OUI_IEEE_8021Qbg22,
				      LLDP_EVB22_SUBTYPE))) {
		LLDPAD_ERR("%s:%s evb protocol already enabled\n",
			   __func__, cmd->ifname);
		return cmd_failed;
	}
	return _set_arg_tlvtxenable(cmd, arg, argvalue, true);
}

static int get_arg_fmode(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			 char *obuf, int obuf_len)
{
	cmd_status good_cmd = evb_cmdok(cmd, cmd_gettlv);
	char *s;
	u8 mode;

	if (good_cmd != cmd_success)
		return good_cmd;

	mode = evb_conf_fmode(cmd->ifname, cmd->type);
	if (mode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)
		s = VAL_EVB_FMODE_REFLECTIVE_RELAY;
	else
		s = VAL_EVB_FMODE_BRIDGE;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);
	return cmd_success;
}

static int _set_arg_fmode(struct cmd *cmd, const char *argvalue, bool test)
{
	u8 smode = 0;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	if (!strcasecmp(argvalue, VAL_EVB_FMODE_BRIDGE))
		smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;
	if (!strcasecmp(argvalue, VAL_EVB_FMODE_REFLECTIVE_RELAY))
		smode = LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	if (smode == 0)
		return cmd_bad_params;

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (ed) {
		if (vdp_vsis(ed->ifname))
			return cmd_failed;
	}

	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.fmode",
		 TLVID_PREFIX, cmd->tlvid);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)) {
		LLDPAD_ERR("%s: saving EVB forwarding mode failed\n",
			   cmd->ifname);
		return cmd_failed;
	}

	if (ed)
		ed->policy.smode = smode;

	LLDPAD_INFO("%s: changed EVB forwarding mode (%s)\n", cmd->ifname,
		    argvalue);
	somethingChangedLocal(cmd->ifname, cmd->type);
	return cmd_success;
}

static int set_arg_fmode(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			 UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_fmode(cmd, argvalue, false);
}

static int test_arg_fmode(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			  UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_fmode(cmd, argvalue, true);
}

static int
get_arg_capabilities(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		     char *obuf, int obuf_len)
{
	int comma = 0;
	char t[EVB_BUF_SIZE];
	u8 scap;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	scap = evb_conf_capa(cmd->ifname, cmd->type);
	memset(t, 0, sizeof t);
	if (scap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE) {
		strcat(t, VAL_EVB_CAPA_RTE);
		comma = 1;
	}
	if (scap & LLDP_EVB_CAPABILITY_PROTOCOL_ECP) {
		if (comma)
			strcat(t, " ");
		strcat(t, VAL_EVB_CAPA_ECP);
		comma = 1;
	}
	if (scap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP) {
		if (comma)
			strcat(t, " ");
		strcat(t, VAL_EVB_CAPA_VDP);
	}
	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(t), t);
	return cmd_success;
}

/*
 * Check for valid parameters: rte,ecp,vpd,none and combinations thereof
 */
static int check_capabilities(const char *capabilities, u8 *scap)
{
	char *cp, *old_string, *string;
	int retcode = 0;

	*scap = 0;
	old_string = string = strdup(capabilities);
	if (!string)
		return -1;
	while ((cp = strtok(string, ", "))) {
		if (!strcasecmp(cp, VAL_EVB_CAPA_RTE))
			*scap |= LLDP_EVB_CAPABILITY_PROTOCOL_RTE;
		else if (!strcasecmp(cp, VAL_EVB_CAPA_ECP))
			*scap |= LLDP_EVB_CAPABILITY_PROTOCOL_ECP;
		else if (!strcasecmp(cp, VAL_EVB_CAPA_VDP))
			*scap |= LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
		else if (!strcasecmp(cp, VAL_EVB_CAPA_NONE)) {
			if (*scap)		/* Invalid combination */
				retcode = -1;
			break;
		} else {
			retcode = -1;
			break;
		}
		string = 0;
	}
	free(old_string);
	return retcode;
}

static int
_set_arg_capabilities(struct cmd *cmd, const char *argvalue, bool test)
{
	u8 scap = 0;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	if (check_capabilities(argvalue, &scap) < 0)
		return cmd_bad_params;

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (ed)
		if (vdp_vsis(ed->ifname))
			return cmd_failed;
	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.capabilities",
		 TLVID_PREFIX, cmd->tlvid);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)) {
		LLDPAD_ERR("%s: saving EVB capabilities (%#x) failed\n",
			cmd->ifname, scap);
		return cmd_failed;
	}

	if (ed)
		ed->policy.scap = scap;
	LLDPAD_INFO("%s: changed EVB capabilities (%#x)\n", cmd->ifname, scap);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int
set_arg_capabilities(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		     UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_capabilities(cmd, argvalue, false);
}

static int
test_arg_capabilities(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		      UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_capabilities(cmd, argvalue, true);
}

static int get_arg_rte(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	char s[EVB_BUF_SIZE];
	u8 rte;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	rte = evb_conf_rte(cmd->ifname, cmd->type);

	if (sprintf(s, "%i", rte) <= 0)
		return cmd_invalid;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(s), s);

	return cmd_success;
}

static int _set_arg_rte(struct cmd *cmd, const char *argvalue, bool test)
{
	int value;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed = NULL;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	value = atoi(argvalue);
	if ((value < 0) || value > LLDP_EVB_DEFAULT_MAX_RTE)
		return cmd_bad_params;

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (ed)
		if (vdp_vsis(ed->ifname))
			return cmd_failed;
	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.rte", TLVID_PREFIX,
		 cmd->tlvid);
	if (set_cfg(cmd->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)){
		LLDPAD_ERR("%s: error saving EVB rte (%d)\n", cmd->ifname,
			   value);
		return cmd_failed;
	}

	if (ed)
		ed->policy.rte = value;
	LLDPAD_INFO("%s: changed EVB rte (%#x)\n", cmd->ifname, value);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_rte(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		       UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_rte(cmd, argvalue, false);
}

static int test_arg_rte(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_rte(cmd, argvalue, true);
}

static int get_arg_vsis(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			char *obuf, int obuf_len)
{
	char s[EVB_BUF_SIZE];
	u16 svsi;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	svsi = evb_conf_vsis(cmd->ifname, cmd->type);

	if (sprintf(s, "%04i", svsi) <= 0)
		return cmd_invalid;
	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);
	return cmd_success;
}

static int _set_arg_vsis(struct cmd *cmd, const char *argvalue, bool test)
{
	int value;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;
	cmd_status good_cmd = evb_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;

	value = atoi(argvalue);
	if ((value < 0) || (value > LLDP_EVB_DEFAULT_MAX_VSI))
		return cmd_bad_params;

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (ed)
		if (vdp_vsis(ed->ifname))
			return cmd_failed;
	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.vsis", TLVID_PREFIX,
		 cmd->tlvid);
	if (set_cfg(cmd->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)){
		LLDPAD_ERR("%s: error saving EVB vsi (%d)\n", cmd->ifname,
			   value);
		return cmd_failed;
	}

	if (ed)
		ed->policy.svsi = htons(value);
	LLDPAD_INFO("%s: changed EVB vsis (%#x)\n", cmd->ifname, value);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_vsis(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_vsis(cmd, argvalue, false);
}

static int test_arg_vsis(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			 UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_vsis(cmd, argvalue, true);
}

static struct arg_handlers arg_handlers[] = {
	{
		.arg = ARG_EVB_FORWARDING_MODE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_fmode,
		.handle_set = set_arg_fmode,
		.handle_test = test_arg_fmode
	},
	{
		.arg = ARG_EVB_CAPABILITIES,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_capabilities,
		.handle_set = set_arg_capabilities,
		.handle_test = test_arg_capabilities
	},
	{
		.arg = ARG_EVB_VSIS,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_vsis,
		.handle_set = set_arg_vsis,
		.handle_test = test_arg_vsis
	},
	{	.arg = ARG_EVB_RTE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rte,
		.handle_set = set_arg_rte,
		.handle_test = test_arg_rte
	},
	{
		.arg = ARG_TLVTXENABLE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_tlvtxenable,
		.handle_set = set_arg_tlvtxenable,
		.handle_test = test_arg_tlvtxenable
	},
	{
		.arg = 0
	}
};

struct arg_handlers *evb_get_arg_handlers()
{
	return &arg_handlers[0];
}
