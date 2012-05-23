/*******************************************************************************
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

*******************************************************************************/

#include <stdio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include "lldp.h"
#include "lldpad.h"
#include "lldp_mand_clif.h"
#include "lldp_8021qaz_cmds.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "config.h"
#include "lldp/ports.h"
#include "lldp/states.h"
#include "lldp_8021qaz.h"
#include "lldp_rtnl.h"
#include "lldpad_shm.h"
#include "messages.h"
#include "lldp_util.h"

static int get_arg_dcbx_mode(struct cmd *, char *, char *, char *, int);
static int set_arg_dcbx_mode(struct cmd *, char *, char *, char *, int);
static int test_arg_dcbx_mode(struct cmd *, char *, char *, char *, int);

static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int test_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);

static int get_arg_willing(struct cmd *, char *, char *, char *, int);
static int set_arg_willing(struct cmd *, char *, char *, char *, int);
static int test_arg_willing(struct cmd *, char *, char *, char *, int);

static int get_arg_numtc(struct cmd *, char *, char *, char *, int);
static int test_arg_numtc(struct cmd *, char *, char *, char *, int);

static int get_arg_up2tc(struct cmd *, char *, char *, char *, int);
static int set_arg_up2tc(struct cmd *, char *, char *, char *, int);
static int test_arg_up2tc(struct cmd *, char *, char *, char *, int);

static int get_arg_tcbw(struct cmd *, char *, char *, char *, int);
static int set_arg_tcbw(struct cmd *, char *, char *, char *, int);
static int test_arg_tcbw(struct cmd *, char *, char *, char *, int);

static int get_arg_tsa(struct cmd *, char *, char *, char *, int);
static int set_arg_tsa(struct cmd *, char *, char *, char *, int);
static int test_arg_tsa(struct cmd *, char *, char *, char *, int);

static int get_arg_enabled(struct cmd *, char *, char *, char *, int);
static int set_arg_enabled(struct cmd *, char *, char *, char *, int);
static int test_arg_enabled(struct cmd *, char *, char *, char *, int);

static int get_arg_delay(struct cmd *, char *, char *, char *, int);
static int set_arg_delay(struct cmd *, char *, char *, char *, int);
static int test_arg_delay(struct cmd *, char *, char *, char *, int);

static int get_arg_app(struct cmd *, char *, char *, char *, int);
static int set_arg_app(struct cmd *, char *, char *, char *, int);
static int test_arg_app(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
	{	.arg = ARG_DCBX_MODE, .arg_class = TLV_ARG,
		.handle_get = get_arg_dcbx_mode,
		.handle_set = set_arg_dcbx_mode,
		.handle_test = test_arg_dcbx_mode, },
	{	.arg = ARG_TLVTXENABLE, .arg_class = TLV_ARG,
		.handle_get = get_arg_tlvtxenable,
		.handle_set = set_arg_tlvtxenable,
		.handle_test = test_arg_tlvtxenable, },
	{	.arg = ARG_WILLING, .arg_class = TLV_ARG,
		.handle_get = get_arg_willing,
		.handle_set = set_arg_willing,
		.handle_test = test_arg_willing, },
	{	.arg = ARG_ETS_NUMTCS, .arg_class = TLV_ARG,
		.handle_get = get_arg_numtc,
		/* no set */
		.handle_test = test_arg_numtc, },
	{	.arg = ARG_ETS_UP2TC, .arg_class = TLV_ARG,
		.handle_get = get_arg_up2tc,
		.handle_set = set_arg_up2tc,
		.handle_test = test_arg_up2tc, },
	{	.arg = ARG_ETS_TCBW, .arg_class = TLV_ARG,
		.handle_get = get_arg_tcbw,
		.handle_set = set_arg_tcbw,
		.handle_test = test_arg_tcbw, },
	{	.arg = ARG_ETS_TSA, .arg_class = TLV_ARG,
		.handle_get = get_arg_tsa,
		.handle_set = set_arg_tsa,
		.handle_test = test_arg_tsa, },
	{	.arg = ARG_PFC_ENABLED, .arg_class = TLV_ARG,
		.handle_get = get_arg_enabled,
		.handle_set = set_arg_enabled,
		.handle_test = test_arg_enabled, },
	{	.arg = ARG_PFC_DELAY, .arg_class = TLV_ARG,
		.handle_get = get_arg_delay,
		.handle_set = set_arg_delay,
		.handle_test = test_arg_delay, },
	{	.arg = ARG_APP, .arg_class = TLV_ARG,
		.handle_get = get_arg_app,
		.handle_set = set_arg_app,
		.handle_test = test_arg_app, },
	{ .arg = 0 }
};

static int
get_arg_dcbx_mode(struct cmd *cmd, char *args, UNUSED char *arg_value,
		  char *obuf, int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8):
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	switch (lldpad_shm_get_dcbx(cmd->ifname)) {
	case dcbx_subtype0:
		snprintf(buf, sizeof(buf), "auto");
		break;
	case dcbx_subtype1:
		snprintf(buf, sizeof(buf), "CIN");
		break;
	case dcbx_subtype2:
		snprintf(buf, sizeof(buf), "CEE");
		break;
	default:
		snprintf(buf, sizeof(buf), "unknown");
		break;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int set_arg_dcbx_mode(struct cmd *cmd, UNUSED char *args,
			     char *arg_value, char *obuf, int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8):
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (strcmp(arg_value, "reset"))
		return cmd_invalid;

	lldpad_shm_set_dcbx(cmd->ifname, dcbx_subtype0);
	snprintf(obuf, obuf_len, "mode = %s\n", arg_value);

	return cmd_success;
}

static int
test_arg_dcbx_mode(UNUSED struct cmd *cmd, UNUSED char *args,
		   UNUSED char *arg_value, UNUSED char *obuf,
		   UNUSED int obuf_len)
{
	return cmd_success;
}

static int get_arg_willing(struct cmd *cmd, char *args,
			   UNUSED char *arg_value, char *obuf, int obuf_len)
{
	int willing;
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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

	if (willing)
		snprintf(obuf, obuf_len, "%02x%s%04x%s",
			(unsigned int) strlen(args), args,
			(unsigned int) strlen(VAL_YES), VAL_YES);
	else
		snprintf(obuf, obuf_len, "%02x%s%04x%s",
			(unsigned int) strlen(args), args,
			(unsigned int) strlen(VAL_NO), VAL_NO);

	return cmd_success;
}

static int _set_arg_willing(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len, bool test)
{
	int willing;
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;



	/* To remain backward compatible and make it easier
	 * for everyone use to {0|1} notation we still support
	 * this but also support english variants as well
	 */
	if (!strcasecmp(arg_value, VAL_YES))
		willing = 1;
	else if (!strcasecmp(arg_value, VAL_NO))
		willing = 0;
	else {
		char *end;

		errno = 0;
		willing = strtol(arg_value, &end, 10);

		if (end == arg_value || *end != '\0')
			return cmd_invalid;

		if (errno || willing < 0)
			return cmd_invalid;
	}

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		if (!test)
			tlvs->ets->cfgl->willing = !!willing;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		if (!test)
			tlvs->pfc->local.willing = !!willing;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (test)
		return cmd_success;

	snprintf(obuf, obuf_len, "willing = %s\n",
		 !!willing ? VAL_YES : VAL_NO);

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &willing,
			   CONFIG_TYPE_INT);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_willing(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_willing(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_willing(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_willing(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_numtc(struct cmd *cmd, char *args,
			 UNUSED char *arg_value, char *obuf, int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		return cmd_not_applicable;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%i",
		(unsigned int) strlen(args), args, 1, tlvs->ets->cfgl->max_tcs);

	return cmd_success;
}

static int test_arg_numtc(UNUSED struct cmd *cmd, UNUSED char *args,
			  UNUSED char *arg_value,
			  UNUSED char *obuf, UNUSED int obuf_len)
{
	return cmd_invalid;
}

static int get_arg_up2tc(struct cmd *cmd, char *args,
			 UNUSED char *arg_value,
			 char *obuf, UNUSED int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	u32 *pmap;
	int i;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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

		if (i)
			snprintf(cat, sizeof(cat), ",%i:%i", i,
						get_prio_map(*pmap, i));
		else
			snprintf(cat, sizeof(cat), "%i:%i", i,
						get_prio_map(*pmap, i));
		strncat(buf, cat, sizeof(buf) - strlen(buf) - 1);
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int
_set_arg_up2tc(struct cmd *cmd, char *args, const char *arg_value,
	       char *obuf, int obuf_len, bool test)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	char *toked_maps, *parse;
	u32 *pmap;
	u32 save_pmap;
	u8 max;
	int i, err = cmd_success;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
		pmap = &tlvs->ets->cfgl->prio_map;
		max = tlvs->ets->cfgl->max_tcs;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
		pmap = &tlvs->ets->recl->prio_map;
		max = MAX_TCS;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}
	save_pmap = *pmap;

	parse = strdup(arg_value);
	if (!parse)
		return cmd_failed;

	/* Parse comma seperated string ex: "1:ets,2:strict,0:vendor" */
	if (strcmp(parse, "none")) {
		toked_maps = strtok(parse, ",");

		while (toked_maps) {
			char *end;
			int tc, prio;
			u32 mask;

			errno = 0;
			prio = strtol(toked_maps, &end, 10);

			if (*end != ':') {
				snprintf(obuf, obuf_len - 1,
					 ": error: %s", toked_maps);
				err = cmd_invalid;
				goto invalid;
			}

			if (errno || prio < 0) {
				snprintf(obuf, obuf_len - 1,
					 ": error: negative prio(%i)", prio);
				err = cmd_invalid;
				goto invalid;
			}

			if (prio > 7) {
				snprintf(obuf, obuf_len - 1,
					 ": error: prio(%i) > 7", prio);
				err = cmd_invalid;
				goto invalid;
			}

			errno = 0;
			tc = strtol(&toked_maps[2], &end, 10);

			if (end == &toked_maps[2] || *end != '\0') {
				snprintf(obuf, obuf_len - 1,
					 ": error: %s", toked_maps);
				err = cmd_invalid;
				goto invalid;
			}

			if (errno || tc < 0) {
				snprintf(obuf, obuf_len - 1,
					 ": error: negative tc(%i)", tc);
				err = cmd_invalid;
				goto invalid;
			}

			if (tc > (max - 1)) {
				snprintf(obuf, obuf_len - 1,
					 ": error: tc(%i) > max tc(%i)",
					 tc, max - 1);
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

	if (test) {
		*pmap = save_pmap;
		free(parse);
		return cmd_success;
	}

	/* Build output buffer */
	strncat(obuf, "up2tc = ", obuf_len - strlen(obuf) - 1);
	for (i = 0; i < 8; i++) {
		char cat[5];

		snprintf(cat, sizeof(cat), "%i:%i ", i, get_prio_map(*pmap, i));
		strncat(obuf, cat, obuf_len - strlen(obuf) - 1);
	}
	strncat(obuf, "\n", obuf_len - strlen(obuf) - 1);

	/* Update configuration file with new attribute */
	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname, cmd->type);
invalid:
	free(parse);
	return err;
}

static int set_arg_up2tc(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_up2tc(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_up2tc(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_up2tc(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_tcbw(struct cmd *cmd, char *args,
			UNUSED char *arg_value, char *obuf, UNUSED int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	int i;
	u8 *bmap;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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
		if (i)
			snprintf(cat, sizeof(cat), ",%i", bmap[i]);
		else
			snprintf(cat, sizeof(cat), "%i", bmap[i]);
		strncat(buf, cat, sizeof(buf) - strlen(buf) - 1);
	}

	sprintf(obuf, "%02x%s%04x%s", (unsigned int) strlen(args),
		args, (unsigned int) strlen(buf), buf);

	return cmd_success;
}

static int
_set_arg_tcbw(struct cmd *cmd, char *args, const char *arg_value,
	      char *obuf, int obuf_len, bool test)
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
		return cmd_device_not_found;

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
	} else if (test) {
		free(parse);
		return cmd_success;
	} else {
		memcpy(tcbw, percent, sizeof(*tcbw) * MAX_TCS);
	}

	strncat(obuf, "tcbw = ", obuf_len - strlen(obuf) - 1);
	for (i = 0; i < 8; i++) {
		char cat[5];
		snprintf(cat, sizeof(cat), "%i%% ", percent[i]);
		printf("%i%% ", percent[i]);
		strncat(obuf, cat, obuf_len - strlen(obuf) - 1);
	}
	strncat(obuf, "\n", obuf_len - strlen(obuf) - 1);

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname, cmd->type);
invalid:
	free(parse);
	return err;
}

static int set_arg_tcbw(struct cmd *cmd, char *args,
			char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_tcbw(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_tcbw(struct cmd *cmd, char *args,
			char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_tcbw(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_tsa(struct cmd *cmd, char *args, UNUSED char *arg_value,
		       char *obuf, UNUSED int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[250] = "";
	int i;
	u8 *tsa;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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
		char cnt[4];
		int space_left;

		if (i)
			snprintf(cnt, sizeof(cnt), ",%i:", i);
		else
			snprintf(cnt, sizeof(cnt), "%i:", i);
		strncat(buf, cnt, sizeof(buf) - strlen(buf) - 1);

		space_left = sizeof(buf) - strlen(buf) - 1;
		switch (tsa[i]) {
		case IEEE8021Q_TSA_STRICT:
			strncat(buf, "strict", space_left);
			break;
		case IEEE8021Q_TSA_CBSHAPER:
			strncat(buf, "cb_shaper", space_left);
			break;
		case IEEE8021Q_TSA_ETS:
			strncat(buf, "ets", space_left);
			break;
		case IEEE8021Q_TSA_VENDOR:
			strncat(buf, "vendor", space_left);
			break;
		default:
			strncat(buf, "unknown", space_left);
			break;
		}
	}

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);


	return cmd_success;
}

static int
_set_arg_tsa(struct cmd *cmd, char *args, const char *arg_value,
	     char *obuf, int obuf_len, bool test)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	char *toked_maps, *parse;
	int i, err = cmd_success;
	u8 *tsa;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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

			if (!test)
				tsa[tc] = type;
			toked_maps = strtok(NULL, ",");
		}
	} else if (!test) {
		memset(tsa, 0, sizeof(tsa));
	}

	if (test) {
		free(parse);
		return cmd_success;
	}

	strncat(obuf, "TSA = ", obuf_len - strlen(obuf) - 1);
	for (i = 0; i < 8; i++) {
		char cnt[3];
		int space_left;

		snprintf(cnt, sizeof(cnt), "%i:", i);
		strncat(obuf, cnt, obuf_len - strlen(obuf) - 1);

		space_left = obuf_len - strlen(obuf) - 1;
		switch (tsa[i]) {
		case IEEE8021Q_TSA_STRICT:
			strncat(obuf, "strict ", space_left);
			break;
		case IEEE8021Q_TSA_CBSHAPER:
			strncat(obuf, "cb_shaper ", space_left);
			break;
		case IEEE8021Q_TSA_ETS:
			strncat(obuf, "ets ", space_left);
			break;
		case IEEE8021Q_TSA_VENDOR:
			strncat(obuf, "vendor ", space_left);
			break;
		default:
			strncat(obuf, "unknown ", space_left);
			break;
		}
	}
	strncat(obuf, "\n", obuf_len - strlen(obuf) - 1);

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &arg_value,
			   CONFIG_TYPE_STRING);
	somethingChangedLocal(cmd->ifname, cmd->type);
invalid:
	free(parse);
	return err;
}

static int set_arg_tsa(struct cmd *cmd, char *args, char *arg_value,
			char *obuf, int obuf_len)
{
	return _set_arg_tsa(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_tsa(struct cmd *cmd, char *args, char *arg_value,
			char *obuf, int obuf_len)
{
	return _set_arg_tsa(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_enabled(struct cmd *cmd, char *args, UNUSED char *arg_value,
			   char *obuf, UNUSED int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	char buf[20] = "";
	int i;
	bool first;
	u8 pfc;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	pfc = tlvs->pfc->local.pfc_enable;

	first = true;
	for (i = 0; i < 8; i++) {
		if (pfc & (1 << i)) {
			char val[3];

			if (first) {
				snprintf(val, sizeof(val), "%i", i);
				first = false;
			} else {
				snprintf(val, sizeof(val), ",%i", i);
			}
			strncat(buf, val, sizeof(buf) - strlen(buf) - 1);
		}
	}

	sprintf(obuf, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(buf), buf);


	return cmd_success;
}

static int _set_arg_enabled(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len, bool test)
{
	struct ieee8021qaz_tlvs *tlvs;
	char *priority, *parse;
	char arg_path[256];
	int mask = 0;
	bool first;
	int i, err = cmd_success;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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
			int prio;
			char *end;

			errno = 0;
			prio = strtol(priority, &end, 10);

			if (end == priority || *end != '\0')
				return cmd_invalid;

			if (errno || prio < 0)
				return cmd_invalid;

			if (prio > 7) {
				err = cmd_invalid;
				goto invalid;
			}
			mask |= 1 << prio;
			priority = strtok(NULL, ",");
		}
	}

	if (test) {
		free(parse);
		return cmd_success;
	}

	first = true;
	strncat(obuf, "prio = ", obuf_len - strlen(obuf) - 1);
	for (i = 0; i < 8; i++) {
		if (mask & (1 << i)) {
			char val[3];

			if (first) {
				snprintf(val, sizeof(val), "%i", i);
				first = false;
			} else {
				snprintf(val, sizeof(val), ",%i", i);
			}
			strncat(obuf, val, obuf_len - strlen(obuf) - 1);
		}
	}
	strncat(obuf, "\n", obuf_len - strlen(obuf) - 1);

	/* Set configuration */
	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s", TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &mask,
			   CONFIG_TYPE_INT);
	tlvs->pfc->local.pfc_enable = mask;
	somethingChangedLocal(cmd->ifname, cmd->type);
invalid:
	free(parse);
	return err;
}

static int set_arg_enabled(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_enabled(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_enabled(struct cmd *cmd, char *args,
			   char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_enabled(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_delay(struct cmd *cmd, char *args,
			 UNUSED char *arg_value, char *obuf, int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%02x",
		(unsigned int) strlen(args), args, 2,
		tlvs->pfc->local.delay);

	return cmd_success;
}

static int _set_arg_delay(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf, int obuf_len, bool test)
{
	struct ieee8021qaz_tlvs *tlvs;
	char arg_path[256];
	unsigned int delay = atoi(arg_value);

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (test)
		return cmd_success;

	tlvs->pfc->local.delay = delay;

	snprintf(obuf, obuf_len, "delay = %i\n", delay);

	/* Set configuration */
	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s", TLVID_PREFIX, cmd->tlvid, args);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &delay,
			   CONFIG_TYPE_INT);

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_delay(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_delay(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_delay(struct cmd *cmd, char *args,
			 char *arg_value, char *obuf, int obuf_len)
{
	return _set_arg_delay(cmd, args, arg_value, obuf, obuf_len, true);
}

static int get_arg_app(struct cmd *cmd, char *args, UNUSED char *arg_value,
		       char *obuf, int obuf_len)
{
	struct ieee8021qaz_tlvs *tlvs;
	int  i = 0;
	struct app_obj *np;
	char app_buf[2048] = "(prio,sel,proto)\n";

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	LIST_FOREACH(np, &tlvs->app_head, entry) {
		char new_app[80];
		char state[15];
		struct dcb_app *dcb_app = &np->app;

		switch (np->hw) {
		case IEEE_APP_SET:
			strcpy(state, "pending set");
			break;
		case IEEE_APP_DEL:
			strcpy(state, "pending delete");
			break;
		case IEEE_APP_DONE:
			strcpy(state, "set");
			break;
		default:
			strcpy(state, "unknown");
			break;
		}

		if (dcb_app->selector == 1) {
			snprintf(new_app, sizeof(new_app),
				"%i:(%i,%i,0x%04x) %s (%s)\n", i,
				dcb_app->priority,
				dcb_app->selector,
				dcb_app->protocol,
				np->peer ? "peer" : "local",
				state);
		} else {
			snprintf(new_app, sizeof(new_app),
				"%i:(%i,%i,%i) %s hw (%s)\n", i,
				dcb_app->priority,
				dcb_app->selector,
				dcb_app->protocol,
				np->peer ? "peer" : "local",
				state);
		}
		strncat(app_buf, new_app, sizeof(app_buf) - strlen(app_buf) - 2);
		i++;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		(unsigned int) strlen(args), args,
		(unsigned int) strlen(app_buf), app_buf);


	return cmd_success;
}

static int _set_arg_app(struct cmd *cmd, char *args, char *arg_value,
			char *obuf, int obuf_len, bool test)
{
	struct ieee8021qaz_tlvs *tlvs;
	char *app_tuple, *parse, *end;
	char arg_path[256];
	char arg_parent[256];
	char arg_name[256];
	char new_argval[16];
	const char *pp = &new_argval[0];
	int prio, sel;
	long pid;
	struct app_obj *np;
	int i, res;
	int unused;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	tlvs = ieee8021qaz_data(cmd->ifname);
	if (!tlvs)
		return cmd_device_not_found;

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

	errno = 0;
	pid = strtol(app_tuple, &end, 0);

	/* Verify input is valid hex or integer */
	if (errno)
		goto err;

	/* Verify input does not contain extra input */
	if (end == app_tuple || *end != '\0')
		goto err;

	/* Verify priority and selector within valid  IEEE range */
	if (prio < 0 || prio > 7 ||
	    sel < 1 || sel > 4 ||
	    pid > 65535 || pid < 0)
		goto err;

	free(parse);

	if (test)
		return cmd_success;

	snprintf(new_argval, sizeof(new_argval),
		 "%1u,%1u,%5u", (u8) prio, (u8) sel, (u16)pid);

	/* Scan APP entries in config file */
	unused = -1;
	for (i = 0; i < MAX_APP_ENTRIES; i++) {
		const char *dummy = NULL;

		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s%i",
			 TLVID_PREFIX,
			 TLVID_8021(LLDP_8021QAZ_APP), ARG_APP, i);
		res = get_config_setting(cmd->ifname, cmd->type, arg_path,
					 &dummy, CONFIG_TYPE_STRING);

		if (res) {
			if (unused < 0)
				unused = i;
			continue;
		}

		/* found an existing entry */
		if (strcmp(dummy, new_argval) == 0) {
			if (cmd->ops & op_delete) {
				unused = 1;
				snprintf(arg_parent, sizeof(arg_parent),
					 "%s%08x", TLVID_PREFIX,
					 TLVID_8021(LLDP_8021QAZ_APP));
				snprintf(arg_name, sizeof(arg_name), "%s%i",
					 ARG_APP, i);
				res = remove_config_setting(cmd->ifname,
						cmd->type, arg_parent,
						arg_name);
			}
		}
	}

	if (unused < 0)
		return cmd_failed;

	/* Build app noting we verified prio, sel, and pid inputs */
	ieee8021qaz_mod_app(&tlvs->app_head, 0, (u8) prio, (u8) sel, (u16) pid,
		(cmd->ops & op_delete) ? op_delete : 0);
	ieee8021qaz_app_sethw(cmd->ifname, &tlvs->app_head);

	i = 0;
	LIST_FOREACH(np, &tlvs->app_head, entry) {
		char new_app[80];
		char state[15];
		struct dcb_app *dcb_app = &np->app;

		switch (np->hw) {
		case IEEE_APP_SET:
			strcpy(state, "pending set");
			break;
		case IEEE_APP_DEL:
			strcpy(state, "pending delete");
			break;
		case IEEE_APP_DONE:
			strcpy(state, "set");
			break;
		default:
			strcpy(state, "unknown");
			break;
		}

		if (dcb_app->selector == 1) {
			snprintf(new_app, sizeof(new_app),
				"%i:(%i,%i,0x%04x) %s (%s)\n", i,
				dcb_app->priority,
				dcb_app->selector,
				dcb_app->protocol,
				np->peer ? "peer" : "local",
				state);
		} else {
			snprintf(new_app, sizeof(new_app),
				"%i:(%i,%i,%i) %s (%s)\n", i,
				dcb_app->priority,
				dcb_app->selector,
				dcb_app->protocol,
				np->peer ? "peer" : "local",
				state);
		}
		strncat(obuf, new_app, obuf_len - strlen(obuf) - 2);
		i++;
	}

	somethingChangedLocal(cmd->ifname, cmd->type);

	if (cmd->ops & op_delete)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path),
		 "%s%08x.%s%i", TLVID_PREFIX, cmd->tlvid, args, unused);

	set_config_setting(cmd->ifname, cmd->type, arg_path, &pp,
			   CONFIG_TYPE_STRING);

	return cmd_success;

err:
	free(parse);
	return cmd_invalid;
}

static int set_arg_app(struct cmd *cmd, char *args, char *arg_value,
		       char *obuf, int obuf_len)
{
	return _set_arg_app(cmd, args, arg_value, obuf, obuf_len, false);
}

static int test_arg_app(struct cmd *cmd, char *args, char *arg_value,
			char *obuf, int obuf_len)
{
	return _set_arg_app(cmd, args, arg_value, obuf, obuf_len, true);
}

static int
get_arg_tlvtxenable(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		    char *obuf, int obuf_len)
{
	int value;
	char *s;
	char arg_path[256];

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (!is_tlv_txdisabled(cmd->ifname, cmd->type, cmd->tlvid))
			value = true;
		else
			value = false;
		break;
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC:
	case (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (is_tlv_txenabled(cmd->ifname, cmd->type, cmd->tlvid))
			value = true;
		else
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

	snprintf(obuf, obuf_len, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		 (unsigned int)strlen(s), s);

	return cmd_success;
}

static int _set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf, int obuf_len, bool test)
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
	err = get_config_setting(cmd->ifname, cmd->type, arg_path,
				 &curr, CONFIG_TYPE_BOOL);

	if (test)
		return cmd_success;

	snprintf(obuf, obuf_len, "enabled = %s\n", value ? "yes" : "no");

	if (!err && curr == value)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL))
		return cmd_failed;


	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf, int obuf_len)
{
	return _set_arg_tlvtxenable(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf, int obuf_len)
{
	return _set_arg_tlvtxenable(cmd, arg, argvalue, obuf, obuf_len, true);
}

struct arg_handlers *ieee8021qaz_get_arg_handlers()
{
	return &arg_handlers[0];
}
