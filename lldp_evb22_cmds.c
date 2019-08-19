/******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2012

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
#include "lldp_evb22.h"
#include "lldp_tlv.h"
#include "lldp_mand_clif.h"
#include "config.h"
#include "clif_msgs.h"
#include "messages.h"

/*
 * Defines for configuration file name tags.
 */
#define EVB_BUF_SIZE			256
#define EVB_CONF_MODE			"evbmode"
#define EVB_CONF_RRREQ			"evbrrreq"
#define EVB_CONF_RRCAP			"evbrrcap"
#define EVB_CONF_GPID			"evbgpid"
#define EVB_CONF_RETRIES		"ecpretries"
#define EVB_CONF_RTE			"ecprte"
#define EVB_CONF_RWD			"vdprwd"
#define EVB_CONF_RKA			"vdprka"
#define EVB_CONF_BRIDGE			"bridge"
#define EVB_CONF_STATION		"station"

/*
 * Read EVB specific data from the configuration file.
 */
static const char *evb22_conf_string(char *ifname, enum agent_type type,
				   char *ext, int def)
{
	char arg_path[EVB_BUF_SIZE];
	const char *param = NULL;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, TLVID(OUI_IEEE_8021Qbg22, LLDP_EVB22_SUBTYPE),
		 ext);
	if (get_cfg(ifname, type, arg_path, &param, CONFIG_TYPE_STRING))
		LLDPAD_INFO("%s:%s agent %d loading EVB policy for %s"
			    " failed, using default (%d)\n", __func__,
			    ifname, type, ext, def);
	return param;
}

static int evb22_conf_int(char *ifname, enum agent_type type,
			  char *ext, int def, int cfgtype)
{
	char arg_path[EVB_BUF_SIZE];
	int param;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, TLVID(OUI_IEEE_8021Qbg22, LLDP_EVB22_SUBTYPE),
		 ext);
	if (get_cfg(ifname, type, arg_path, &param, cfgtype)) {
		LLDPAD_INFO("%s:%s agent %d loading EVB policy for %s"
			    " failed, using default (%d)\n", __func__,
			    ifname, type, ext, def);
		return def;
	}
	return param;
}

/*
 * Read EXP parameter. Defaults to 8 --> 10 * 2 ^ 8 = 2560us > 2ms.
 */
static int exponent(char *ifname, enum agent_type type, char *txt, int def)
{
	int value;

	value = evb22_conf_int(ifname, type, txt, def, CONFIG_TYPE_INT);
	if (value > 31) {
		LLDPAD_DBG("%s:%s agent %d invalid %s %d\n", __func__,
			   ifname, type, txt, value);
		value = def;
	}
	LLDPAD_DBG("%s:%s agent %d policy %s %d\n", __func__,
		   ifname, type, txt, value);
	return value;
}

/*
 * Read retransmission exponent parameter.
 */
int evb22_conf_rte(char *ifname, enum agent_type type)
{
	return exponent(ifname, type, EVB_CONF_RTE, 8);
}

/*
 * Read reinit keep alive parameter. Same as RTE.
 */
int evb22_conf_rka(char *ifname, enum agent_type type)
{
	return exponent(ifname, type, EVB_CONF_RKA, 20);
}

/*
 * Read resource wait delay parameter. Same as RTE.
 */
int evb22_conf_rwd(char *ifname, enum agent_type type)
{
	return exponent(ifname, type, EVB_CONF_RWD, 20);
}

/*
 * Read max retries parameter. Defaults to 3.
 */
int evb22_conf_retries(char *ifname, enum agent_type type)
{
	int value;

	value = evb22_conf_int(ifname, type, EVB_CONF_RETRIES, 3,
			     CONFIG_TYPE_INT);
	if (value > 7) {
		LLDPAD_DBG("%s:%s agent %d invalid %s %d\n", __func__,
			   ifname, type, EVB_CONF_RETRIES, value);
		value = 3;
	}
	LLDPAD_DBG("%s:%s agent %d policy %s %d\n", __func__,
		   ifname, type, EVB_CONF_RETRIES, value);
	return value;
}

/*
 * Read station group id parameter. Defaults to false.
 */
int evb22_conf_gid(char *ifname, enum agent_type type)
{
	int value;

	value = evb22_conf_int(ifname, type, EVB_CONF_GPID, false,
			     CONFIG_TYPE_BOOL);
	LLDPAD_DBG("%s:%s agent %d policy %s %s\n", __func__,
		   ifname, type, EVB_CONF_GPID, value ? "true" : "false");
	return value;
}

/*
 * Read reflective-relay bridge capability parameter. Defaults to false.
 */
int evb22_conf_rrcap(char *ifname, enum agent_type type)
{
	int value;

	value = evb22_conf_int(ifname, type, EVB_CONF_RRCAP, false,
			     CONFIG_TYPE_BOOL);
	LLDPAD_DBG("%s:%s agent %d policy %s %s\n", __func__,
		   ifname, type, EVB_CONF_RRCAP, value ? "true" : "false");
	return value;
}

/*
 * Read reflective-relay station request parameter. Defaults to false.
 */
int evb22_conf_rrreq(char *ifname, enum agent_type type)
{
	int value;

	value = evb22_conf_int(ifname, type, EVB_CONF_RRREQ, false,
			     CONFIG_TYPE_BOOL);
	LLDPAD_DBG("%s:%s agent %d policy %s %s\n", __func__,
		   ifname, type, EVB_CONF_RRREQ, value ? "true" : "false");
	return value;
}

/*
 * Read station/bridge role from configuration file. Defaults to station
 */
int evb22_conf_evbmode(char *ifname, enum agent_type type)
{
	int mode = EVB_STATION;
	const char *value;

	value = evb22_conf_string(ifname, type, EVB_CONF_MODE, mode);
	if (value) {
		if (!strcasecmp(value, EVB_CONF_BRIDGE))
			mode = EVB_BRIDGE;
		else if (strcasecmp(value, EVB_CONF_STATION)) {
			LLDPAD_ERR("%s:%s agent %d invalid evbmode %s\n",
				   __func__, ifname, type, value);
			value = EVB_CONF_STATION;
		}
	} else
		value = EVB_CONF_STATION;
	LLDPAD_DBG("%s:%s agent %d policy %s %s(%#x)\n", __func__,
		   ifname, type, EVB_CONF_MODE, value, mode);
	return mode;
}

/*
 * Read transmit status from configuration file.
 */
int evb22_conf_enabletx(char *ifname, enum agent_type type)
{
	return is_tlv_txenabled(ifname, type,
				TLVID(OUI_IEEE_8021Qbg22, LLDP_EVB22_SUBTYPE));
}

static int evb22_cmdok(struct cmd *cmd, int expected)
{
	if (cmd->cmd != expected)
		return cmd_invalid;
	switch (cmd->tlvid) {
	case TLVID(OUI_IEEE_8021Qbg22, LLDP_EVB22_SUBTYPE):
		return cmd_success;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}
}

static int get_arg_evbmode(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			   char *obuf, int obuf_len)
{
	struct evb22_data *ed;
	char *s;
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if (evb_ex_evbmode(ed->policy.evb_mode) == EVB_STATION)
		s = EVB_CONF_STATION;
	else
		s = EVB_CONF_BRIDGE;
	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);
	return cmd_success;
}

static int set2_arg_evbmode(struct cmd *cmd, char *arg, const char *argvalue,
			    bool test)
{
	char arg_path[EVB_BUF_SIZE];
	struct evb22_data *ed;
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_settlv);
	u8 mode;

	if (good_cmd != cmd_success)
		return good_cmd;
	if (strcasecmp(argvalue, EVB_CONF_BRIDGE)
	    && strcasecmp(argvalue, EVB_CONF_STATION))
		return cmd_bad_params;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if (test)
		return cmd_success;
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)) {
		LLDPAD_ERR("%s: error saving EVB mode (%s)\n", ed->ifname,
			   argvalue);
		return cmd_failed;
	}
	mode = strcasecmp(argvalue, EVB_CONF_BRIDGE) ? EVB_STATION : EVB_BRIDGE;
	ed->policy.evb_mode = evb_maskoff_evbmode(ed->policy.evb_mode) |
				evb_set_evbmode(mode);
	LLDPAD_INFO("%s: changed EVB mode (%s)\n", ed->ifname, argvalue);
	return cmd_success;
}

static int set_arg_evbmode(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return set2_arg_evbmode(cmd, arg, argvalue, false);
}

static int test_arg_evbmode(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return set2_arg_evbmode(cmd, arg, argvalue, true);
}

static int get_txmit(struct evb22_data *ed)
{
	return ed->txmit;
}

static void set_txmit(struct evb22_data *ed, int value)
{
	ed->txmit = value;
}

static int get_gpid(struct evb22_data *ed)
{
	int mode = evb_ex_evbmode(ed->policy.evb_mode);

	if (mode == EVB_STATION && evb_ex_sgid(ed->policy.station_s))
		return 1;
	if (mode == EVB_BRIDGE && evb_ex_bgid(ed->policy.bridge_s))
		return 1;
	return 0;
}

static void set_gpid(struct evb22_data *ed, int value)
{
	if (evb_ex_evbmode(ed->policy.evb_mode) == EVB_STATION)
		ed->policy.station_s = evb_maskoff_sgid(ed->policy.station_s)
					| evb_set_sgid(value);
	else
		ed->policy.bridge_s = evb_maskoff_bgid(ed->policy.bridge_s)
					| evb_set_bgid(value);
}

static void set_rrcap(struct evb22_data *ed, int value)
{
	ed->policy.bridge_s = evb_maskoff_rrcap(ed->policy.bridge_s)
				| evb_set_rrcap(value);
}

static int get_rrcap(struct evb22_data *ed)
{
	return evb_ex_rrcap(ed->policy.bridge_s);
}

static void set_rrreq(struct evb22_data *ed, int value)
{
	ed->policy.station_s = evb_maskoff_rrreq(ed->policy.station_s)
				| evb_set_rrreq(value);
}

static int get_rrreq(struct evb22_data *ed)
{
	return evb_ex_rrreq(ed->policy.station_s);
}

/*
 * Read a boolean value from the command line argument and apply the new
 * value to parameter.
 */
static int scan_bool(struct cmd *cmd, char *arg, char *argvalue, bool test,
		     void (*fct)(struct evb22_data *, int))
{
	int value;
	char arg_path[EVB_BUF_SIZE];
	struct evb22_data *ed;
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	if (!strcasecmp(argvalue, VAL_YES))
		value = 1;
	else if (!strcasecmp(argvalue, VAL_NO))
		value = 0;
	else
		return cmd_bad_params;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if (test)
		return cmd_success;
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);
	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL)){
		LLDPAD_ERR("%s: error saving EVB enabletx (%s)\n", ed->ifname,
			   argvalue);
		return cmd_failed;
	}
	LLDPAD_INFO("%s: changed EVB %s (%s)\n", ed->ifname, arg, argvalue);
	(*fct)(ed, value);
	somethingChangedLocal(cmd->ifname, cmd->type);
	return cmd_success;
}

static int show_bool(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		     char *obuf, int obuf_len,
		     int (*fct)(struct evb22_data *))
{
	struct evb22_data *ed;
	char *s;
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if ((*fct)(ed))
		s = VAL_YES;
	else
		s = VAL_NO;
	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);
	return cmd_success;
}

static int get_arg_tlvtxenable(struct cmd *cmd, char *arg,
			       UNUSED char *argvalue, char *obuf, int obuf_len)
{
	return show_bool(cmd, arg, argvalue, obuf, obuf_len, get_txmit);
}

static int set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, false, set_txmit);
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
				TLVID(OUI_IEEE_8021Qbg,
				      LLDP_EVB_SUBTYPE))) {
		LLDPAD_ERR("%s:%s evb draft 0.2 protocol already enabled\n",
			   __func__, cmd->ifname);
		return cmd_failed;
	}
	return scan_bool(cmd, arg, argvalue, true, 0);
}

static int get_arg_gpid(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_bool(cmd, arg, argvalue, obuf, obuf_len, get_gpid);
}

static int set_arg_gpid(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, false, set_gpid);
}

static int test_arg_gpid(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, true, 0);
}

static int get_arg_rrcap(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_bool(cmd, arg, argvalue, obuf, obuf_len, get_rrcap);
}

static int set_arg_rrcap(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, false, set_rrcap);
}

static int test_arg_rrcap(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, true, 0);
}

static int get_arg_rrreq(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_bool(cmd, arg, argvalue, obuf, obuf_len, get_rrreq);
}

static int set_arg_rrreq(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, false, set_rrreq);
}

static int test_arg_rrreq(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_bool(cmd, arg, argvalue, true, 0);
}


static void set_retries(struct evb22_data *ed, int value)
{
	ed->policy.r_rte = evb_maskoff_retries(ed->policy.r_rte)
				    | evb_set_retries(value);
}

static int get_retries(struct evb22_data *ed)
{
	return evb_ex_retries(ed->policy.r_rte);
}

static void set_rte(struct evb22_data *ed, int value)
{
	ed->policy.r_rte = evb_maskoff_rte(ed->policy.r_rte)
				    | evb_set_rte(value);
}

static int get_rte(struct evb22_data *ed)
{
	return evb_ex_rte(ed->policy.r_rte);
}

static void set_rwd(struct evb22_data *ed, int value)
{
	ed->policy.evb_mode = evb_maskoff_rwd(ed->policy.evb_mode)
				    | evb_set_rwd(value);
}

static int get_rwd(struct evb22_data *ed)
{
	return evb_ex_rwd(ed->policy.evb_mode);
}

static void set_rka(struct evb22_data *ed, int value)
{
	ed->policy.rl_rka = evb_maskoff_rka(ed->policy.rl_rka)
				    | evb_set_rka(value);
}

static int get_rka(struct evb22_data *ed)
{
	return evb_ex_rka(ed->policy.rl_rka);
}

static int scan_31bit(struct cmd *cmd, char *arg, const char *argvalue,
		      bool test, void (*fct)(struct evb22_data *, int),
		      int limit)
{
	char arg_path[EVB_BUF_SIZE];
	struct evb22_data *ed;
	int value;
	char *endp;
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_settlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	value = strtoul(argvalue, &endp, 0);
	if (*endp != '\0' || value > limit)
		return cmd_bad_params;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if (test)
		return cmd_success;
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);
	if (set_cfg(ed->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_INT)){
		LLDPAD_ERR("%s: error saving EVB %s (%d)\n", ed->ifname, arg,
			   value);
		return cmd_failed;
	}
	LLDPAD_INFO("%s: changed EVB %s (%s)\n", ed->ifname, arg, argvalue);
	(*fct)(ed, value);
	somethingChangedLocal(cmd->ifname, cmd->type);
	return cmd_success;
}

static int show_31bit(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		      char *obuf, int obuf_len,
		      int (*fct)(struct evb22_data *))
{
	struct evb22_data *ed;
	char s[EVB_BUF_SIZE];
	cmd_status good_cmd = evb22_cmdok(cmd, cmd_gettlv);

	if (good_cmd != cmd_success)
		return good_cmd;
	ed = evb22_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;
	if (sprintf(s, "%i", (*fct)(ed)) <= 0)
		return cmd_invalid;
	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);
	return cmd_success;
}

static int get_arg_retries(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_31bit(cmd, arg, argvalue, obuf, obuf_len, get_retries);
}

static int set_arg_retries(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, false, set_retries, 7);
}

static int test_arg_retries(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, true, 0, 7);
}

static int get_arg_rte(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_31bit(cmd, arg, argvalue, obuf, obuf_len, get_rte);
}

static int set_arg_rte(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, false, set_rte, 31);
}

static int test_arg_rte(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, true, 0, 31);
}

static int get_arg_rwd(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_31bit(cmd, arg, argvalue, obuf, obuf_len, get_rwd);
}

static int set_arg_rwd(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, false, set_rwd, 31);
}

static int test_arg_rwd(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, true, 0, 31);
}

static int get_arg_rka(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	return show_31bit(cmd, arg, argvalue, obuf, obuf_len, get_rka);
}

static int set_arg_rka(struct cmd *cmd, char *arg, char *argvalue,
			       UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, false, set_rka, 31);
}

static int test_arg_rka(struct cmd *cmd, char *arg, char *argvalue,
				UNUSED char *obuf, UNUSED int obuf_len)
{
	return scan_31bit(cmd, arg, argvalue, true, 0, 31);
}

static struct arg_handlers arg_handlers[] = {
	{
		.arg = EVB_CONF_RKA,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rka,
		.handle_set = set_arg_rka,
		.handle_test = test_arg_rka
	},
	{
		.arg = EVB_CONF_RWD,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rwd,
		.handle_set = set_arg_rwd,
		.handle_test = test_arg_rwd
	},
	{
		.arg = EVB_CONF_RTE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rte,
		.handle_set = set_arg_rte,
		.handle_test = test_arg_rte
	},
	{
		.arg = EVB_CONF_RETRIES,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_retries,
		.handle_set = set_arg_retries,
		.handle_test = test_arg_retries
	},
	{
		.arg = EVB_CONF_RRREQ,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rrreq,
		.handle_set = set_arg_rrreq,
		.handle_test = test_arg_rrreq
	},
	{
		.arg = EVB_CONF_RRCAP,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_rrcap,
		.handle_set = set_arg_rrcap,
		.handle_test = test_arg_rrcap
	},
	{
		.arg = EVB_CONF_GPID,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_gpid,
		.handle_set = set_arg_gpid,
		.handle_test = test_arg_gpid
	},
	{
		.arg = EVB_CONF_MODE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_evbmode,
		.handle_set = set_arg_evbmode,
		.handle_test = test_arg_evbmode
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

struct arg_handlers *evb22_get_arg_handlers()
{
	return &arg_handlers[0];
}
