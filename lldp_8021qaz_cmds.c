/*******************************************************************************
  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2011 Intel Corporation.

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

#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "lldp.h"
#include "lldpad.h"
#include "lldp_mand_clif.h"
#include "lldp_8021qaz_cmds.h"
#include "clif_msgs.h"
#include "config.h"
#include "lldp/ports.h"
#include "lldp/states.h"
#include "lldp_8021qaz.h"
#include "lldp_rtnl.h"
#include "messages.h"
#include "lldp_util.h"

static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *);

static int get_arg_willing(struct cmd *, char *, char *, char *);
static int set_arg_willing(struct cmd *, char *, char *, char *);

static int get_arg_numtc(struct cmd *, char *, char *, char *);

static int get_arg_up2tc(struct cmd *, char *, char *, char *);
static int set_arg_up2tc(struct cmd *, char *, char *, char *);

static int get_arg_tcbw(struct cmd *, char *, char *, char *);
static int set_arg_tcbw(struct cmd *, char *, char *, char *);

static int get_arg_tsa(struct cmd *, char *, char *, char *);
static int set_arg_tsa(struct cmd *, char *, char *, char *);

static int get_arg_enabled(struct cmd *, char *, char *, char *);
static int set_arg_enabled(struct cmd *, char *, char *, char *);

static int get_arg_delay(struct cmd *, char *, char *, char *);
static int set_arg_delay(struct cmd *, char *, char *, char *);

static int get_arg_app(struct cmd *, char *, char *, char *);
static int set_arg_app(struct cmd *, char *, char *, char *);

static struct arg_handlers arg_handlers[] = {
	{ ARG_TLVTXENABLE, get_arg_tlvtxenable, set_arg_tlvtxenable },
	{ ARG_WILLING, get_arg_willing, set_arg_willing	},
	{ ARG_ETS_NUMTCS, get_arg_numtc,			},
	{ ARG_ETS_UP2TC, get_arg_up2tc, set_arg_up2tc		},
	{ ARG_ETS_TCBW, get_arg_tcbw, set_arg_tcbw		},
	{ ARG_ETS_TSA, get_arg_tsa, set_arg_tsa			},
	{ ARG_PFC_ENABLED, get_arg_enabled, set_arg_enabled	},
	{ ARG_PFC_DELAY, get_arg_delay, set_arg_delay		},
	{ ARG_APP, get_arg_app, set_arg_app			},
	{ NULL }
};

static int get_arg_willing(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf)
{
	int willing;
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		willing = tlvs->ets->cfgl->willing;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		willing = tlvs->pfc->local.willing;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	sprintf(obuf, "%02x%s%04x%i", (unsigned int) strlen(args), args,
		(unsigned int) 1, !!willing);

	return cmd_success;
}

static int set_arg_willing(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf)
{
	long willing = strtol(arg_value, NULL, 10);
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		tlvs->ets->cfgl->willing = !!willing;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		tlvs->pfc->local.willing = !!willing;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &willing, CONFIG_TYPE_INT);
	somethingChangedLocal(cmd->ifname);

	return cmd_success;
}

static int get_arg_numtc(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	sprintf(obuf, "%02x%s%04x%i",
		(unsigned int) strlen(args), args, 1, tlvs->ets->cfgl->max_tcs);

	return cmd_success;
}

static int get_arg_up2tc(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	u32 *pmap;
	int i;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		pmap = &tlvs->ets->cfgl->prio_map;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		pmap = &tlvs->ets->recl->prio_map;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	for (i = 0; i < 8; i++) {
		char cat[5];

		snprintf(cat, sizeof(cat), "%i:%i ", i, get_prio_map(*pmap, i));
		strncat(buf, cat, sizeof(buf) - strlen(buf) - 1);
	}

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int set_arg_up2tc(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	char *toked_maps, *parse;
	u32 *pmap;
	int err = cmd_success;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		pmap = &tlvs->ets->cfgl->prio_map;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		pmap = &tlvs->ets->recl->prio_map;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	/* Parse comma seperated string ex: "1:ets,2:strict,0:vendor" */
	if (strcmp(parse, "none")) {
		toked_maps = strtok(parse, ",");

		while (toked_maps) {
			int tc, prio;
			u32 mask;

			if (toked_maps[1] != ':') {
				err = cmd_invalid;
				goto invalid;
			}

			prio = 0x7 & atoi(toked_maps);
			tc = 0x7 & atoi(&toked_maps[2]);
			if (tc > 7) {
				err = cmd_invalid;
				goto invalid;
			}

			mask = ~(0xffffffff & (0xF << (4 * (7-prio))));
			*pmap &= mask;
			*pmap |= tc << (4 * (7-prio));
			toked_maps = strtok(NULL, ",");
		}
	} else {
		*pmap = 0;
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname);
invalid:
	free(parse);
	return err;
}

static int get_arg_tcbw(struct cmd *cmd, char *args,
			char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	int i;
	u8 *bmap;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		bmap = tlvs->ets->cfgl->tc_bw;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		bmap = tlvs->ets->recl->tc_bw;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	for (i = 0; i < 8; i++) {
		char cat[6];
		snprintf(cat, sizeof(cat), "%i%% ", bmap[i]);
		strncat(buf, cat, sizeof(buf) - strlen(buf) - 1);
	}

	sprintf(obuf, "%02x%s%04x%s", (unsigned int) strlen(args),
		args, (unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int set_arg_tcbw(struct cmd *cmd, char *args,
			char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	char *toked_bw, *parse;
	int i, err = cmd_success;
	u8 *tcbw, percent[8] = {0}, total = 0;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		tcbw = tlvs->ets->cfgl->tc_bw;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		tcbw = tlvs->ets->recl->tc_bw;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	/* Parse comma seperated string ex: "1:ets,2:strict,0:vendor" */
	toked_bw = strtok(parse, ",");

	for (i = 0; i < 8 && toked_bw; i++) {
		percent[i] = atoi(toked_bw);
		toked_bw = strtok(NULL, ",");
	}

	for (i = 0; i < 8; i++)
		total += percent[i];
	if (total != 100) {
		err = cmd_invalid;
		goto invalid;
	} else {
		memcpy(tcbw, percent, sizeof(tcbw));
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname);
invalid:
	free(parse);
	return err;
}

static int get_arg_tsa(struct cmd *cmd, char *args, char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	int i;
	u8 *tsa;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		tsa = tlvs->ets->cfgl->tsa_map;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		tsa = tlvs->ets->recl->tsa_map;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	for (i = 0; i < 8; i++) {
		char cnt[3];
		int space_left;

		snprintf(cnt, sizeof(cnt), "%i:", i);
		strncat(buf, cnt, sizeof(buf) - strlen(buf) - 1);

		space_left = sizeof(buf) - strlen(buf) - 1;
		switch (tsa[i]) {
		case IEEE8021Q_TSA_STRICT:
			strncat(buf, "strict ", space_left);
			break;
		case IEEE8021Q_TSA_CBSHAPER:
			strncat(buf, "cb_shaper ", space_left);
			break;
		case IEEE8021Q_TSA_ETS:
			strncat(buf, "ets ", space_left);
			break;
		case IEEE8021Q_TSA_VENDOR:
			strncat(buf, "vendor ", space_left);
			break;
		default:
			strncat(buf, "unknown ", space_left);
			break;
		}
	}

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int set_arg_tsa(struct cmd *cmd, char *args, char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	char *toked_maps, *parse;
	int err = cmd_success;
	u8 *tsa;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		tsa = tlvs->ets->cfgl->tsa_map;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		tsa = tlvs->ets->recl->tsa_map;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	/* Parse comma seperated string ex: "1:ets,2:strict,0:vendor" */
	if (strcmp(parse, "none")) {
		toked_maps = strtok(parse, ",");

		while (toked_maps) {
			int tc, type;

			if (toked_maps[1] != ':') {
				err = cmd_invalid;
				goto invalid;
			}

			tc = atoi(toked_maps);
			if (tc > 7) {
				err = cmd_invalid;
				goto invalid;
			}

			if ((strcmp(&toked_maps[2], "strict")) == 0)
				type = IEEE8021Q_TSA_STRICT;
			else if ((strcmp(&toked_maps[2], "cb_shaper")) == 0)
				type = IEEE8021Q_TSA_CBSHAPER;
			else if ((strcmp(&toked_maps[2], "ets")) == 0)
				type = IEEE8021Q_TSA_ETS;
			else if ((strcmp(&toked_maps[2], "vendor")) == 0)
				type = IEEE8021Q_TSA_VENDOR;
			else  {
				err = cmd_invalid;
				goto invalid;
			}

			tsa[tc] = type;
			toked_maps = strtok(NULL, ",");
		}
	} else {
		memset(tsa, 0, sizeof(tsa));
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname);
invalid:
	free(parse);
	return err;
}

static int get_arg_enabled(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[20] = " ";
	int i;
	u8 pfc;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	pfc = tlvs->pfc->local.pfc_enable;

	for (i = 0; i < 8; i++) {
		if (pfc & (1 << i)) {
			char val[3];

			snprintf(val, sizeof(val), "%i ", i);
			strncat(buf, val, sizeof(buf) - strlen(buf) - 1);
		}
	}

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int set_arg_enabled(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char *priority, *parse;
	char arg_path[256];
	u8 mask = 0;
	int err = cmd_success;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	/* Parse comma seperated string */
	if (strcmp(arg_value, "none")) {
		priority = strtok(parse, ",");

		while (priority) {
			int prio = atoi(priority);

			if (prio > 7) {
				err = cmd_invalid;
				goto invalid;
			}
			mask |= 1 << prio;
			priority = strtok(NULL, ",");
		}
	}

	/* Set configuration */
	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s", TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &mask, CONFIG_TYPE_INT);
	tlvs->pfc->local.pfc_enable = mask;
	somethingChangedLocal(cmd->ifname);
invalid:
	free(parse);
	return cmd_success;
}

static int get_arg_delay(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	sprintf(obuf, "%02x%s%04x%02x",
		(unsigned int) strlen(args), args, 2,
		tlvs->pfc->local.delay);

	return cmd_success;
}

static int set_arg_delay(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	unsigned int delay = atoi(arg_value);

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	tlvs->pfc->local.delay = delay;

	/* Set configuration */
	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s", TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &delay, CONFIG_TYPE_INT);

	somethingChangedLocal(cmd->ifname);

	return cmd_success;
}

static int get_arg_app(struct cmd *cmd, char *args, char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	struct app_prio *apps;
	int cnt, i;
	char temp[80], app_buf[1024] = "(prio,sel,proto)\n";

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	apps = get_ieee_app(cmd->ifname, &cnt);
	for (i = 0; apps && i < cnt; i++) {
		if ((apps[i].prs & 0x07) == 1) {
			sprintf(temp, "%i:(%i,%i,0x%0004x)\n", i,
				(apps[i].prs & 0xE0) >> 5,
				(apps[i].prs & 0x07),
				apps[i].pid);
		} else {
			sprintf(temp, "%i:(%i,%i,%i)\n", i,
				(apps[i].prs & 0xE0) >> 5,
				(apps[i].prs & 0x07),
				ntohs(apps[i].pid));
		}

		strncat(app_buf, temp, sizeof(app_buf) - strlen(app_buf) - 1);
	}
	free(apps);

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(app_buf), app_buf);

	return cmd_success;
}

static int set_arg_app(struct cmd *cmd, char *args, char *arg_value, char *obuf)
{
	struct ieee8021qaz_tlvs *tlvs;
	char *app_tuple, *parse;
	char arg_path[256];
	u8 prio, sel;
	u16 pid;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	app_tuple = strtok(parse, ",");
	if (!app_tuple)
		goto err;
	prio = atoi(app_tuple);

	app_tuple = strtok(NULL, ",");
	if (!app_tuple)
		goto err;
	sel = atoi(app_tuple);

	app_tuple = strtok(NULL, ",");
	if (!app_tuple)
		goto err;
	pid = atoi(app_tuple);

	ieee8021qaz_add_app(&tlvs->app_head, 0, prio, sel, pid);
	ieee8021qaz_app_sethw(cmd->ifname, &tlvs->app_head);

	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s", TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);

	somethingChangedLocal(cmd->ifname);

	free(parse);
	return cmd_success;
err:
	free(parse);
	return cmd_invalid;
}

static int get_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf)
{
	int value;
	char *s;
	char arg_path[256];

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8):
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (get_config_setting(cmd->ifname, arg_path, (void *)&value,
					CONFIG_TYPE_BOOL))
			value = false;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (value)
		s = VAL_YES;
	else
		s = VAL_NO;

	sprintf(obuf, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		(unsigned int)strlen(s), s);

	return cmd_success;
}

static int set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf)
{
	int value, curr, err;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8):
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (!strcasecmp(argvalue, VAL_YES))
		value = 1;
	else if (!strcasecmp(argvalue, VAL_NO))
		value = 0;
	else
		return cmd_invalid;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, ARG_TLVTXENABLE);
	err = get_config_setting(cmd->ifname, arg_path,
				(void *)&curr, CONFIG_TYPE_BOOL);
	if (!err && curr == value)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, arg_path, (void *)&value, CONFIG_TYPE_BOOL))
		return cmd_failed;

	somethingChangedLocal(cmd->ifname);

	return cmd_success;
}

struct arg_handlers *ieee8021qaz_get_arg_handlers()
{
	return &arg_handlers[0];
}
