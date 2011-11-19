/*******************************************************************************

  implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>

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

*******************************************************************************/

#define _GNU_SOURCE
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_evb.h"
#include "lldp_tlv.h"
#include "lldp_mand_clif.h"
#include "lldp_evb_clif.h"
#include "lldp/ports.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldp/states.h"
#include "messages.h"

static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int test_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);

static int get_arg_fmode(struct cmd *, char *, char *, char *, int);
static int set_arg_fmode(struct cmd *, char *, char *, char *, int);
static int test_arg_fmode(struct cmd *, char *, char *, char *, int);

static int get_arg_rte(struct cmd *, char *, char *, char *, int);
static int set_arg_rte(struct cmd *, char *, char *, char *, int);
static int test_arg_rte(struct cmd *, char *, char *, char *, int);

static int get_arg_vsis(struct cmd *, char *, char *, char *, int);
static int set_arg_vsis(struct cmd *, char *, char *, char *, int);
static int test_arg_vsis(struct cmd *, char *, char *, char *, int);

static int get_arg_capabilities(struct cmd *, char *, char *, char *, int);
static int set_arg_capabilities(struct cmd *, char *, char *, char *, int);
static int test_arg_capabilities(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
	{ ARG_EVB_FORWARDING_MODE, TLV_ARG,
		get_arg_fmode, set_arg_fmode, test_arg_fmode },
	{ ARG_EVB_CAPABILITIES, TLV_ARG,
		get_arg_capabilities, set_arg_capabilities,
		test_arg_capabilities },
	{ ARG_EVB_VSIS, TLV_ARG,
		get_arg_vsis, set_arg_vsis, test_arg_vsis },
	{ ARG_EVB_RTE, TLV_ARG,
		get_arg_rte, set_arg_rte, test_arg_rte },
	{ ARG_TLVTXENABLE, TLV_ARG,
		get_arg_tlvtxenable, set_arg_tlvtxenable,
		test_arg_tlvtxenable },
	{ NULL }
};

static int get_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf, int obuf_len)
{
	int value;
	char *s;
	char arg_path[EVB_BUF_SIZE];

	LLDPAD_DBG("%s(%i): \n", __func__, __LINE__);

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (get_cfg(cmd->ifname, cmd->type, arg_path, &value,
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

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(s), s);

	return cmd_success;
}

static int _set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
				char *obuf, int obuf_len, bool test)
{
	int value;
	char arg_path[EVB_BUF_SIZE];

	LLDPAD_DBG("%s(%i): \n", __func__, __LINE__);

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
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

	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
		 TLVID_PREFIX, cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value, CONFIG_TYPE_BOOL))
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

static int get_arg_fmode(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, int obuf_len)
{
	char *s;
	struct evb_data *ed;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);

	if (!ed)
		return cmd_invalid;

	if (ed->policy->smode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)
		s = VAL_EVB_FMODE_REFLECTIVE_RELAY;
	else
		s = VAL_EVB_FMODE_BRIDGE;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(s), s);

	return cmd_success;
}

static int _set_arg_fmode(struct cmd *cmd, char *arg, const char *argvalue,
			  char *obuf, int obuf_len, bool test)
{
	u8 smode;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);

	if (!ed)
		return cmd_invalid;

	smode = 0;

	if (!strcasecmp(argvalue, VAL_EVB_FMODE_BRIDGE)) {
		smode = LLDP_EVB_CAPABILITY_FORWARD_STANDARD;
	}

	if (!strcasecmp(argvalue, VAL_EVB_FMODE_REFLECTIVE_RELAY)) {
		smode = LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY;
	}

	if (smode == 0) {
		return cmd_invalid;
	} else if (test) {
		return cmd_success;
	} else {
		ed->policy->smode = smode;
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.fmode",
		 TLVID_PREFIX, cmd->tlvid);

	if (set_cfg(ed->ifname, cmd->type, arg_path,  &argvalue,
		    CONFIG_TYPE_STRING)) {
		printf("%s:%s: saving EVB forwarding mode failed.\n",
			__func__, ed->ifname);
		return cmd_invalid;
	}

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_fmode(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, int obuf_len)
{
	return _set_arg_fmode(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_arg_fmode(struct cmd *cmd, char *arg, char *argvalue,
			  char *obuf, int obuf_len)
{
	return _set_arg_fmode(cmd, arg, argvalue, obuf, obuf_len, true);
}

static int get_arg_capabilities(struct cmd *cmd, char *arg, char *argvalue,
				char *obuf, int obuf_len)
{
	int c;
	char *s, *t;
	struct evb_data *ed;

	printf("%s(%i): arg %s, argvalue %s !\n", __func__, __LINE__, arg, argvalue);

	s = t = malloc(EVB_BUF_SIZE);

	if (!s)
		goto out_free;

	memset(s, 0, EVB_BUF_SIZE);

	if (cmd->cmd != cmd_gettlv)
		goto out_free;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		goto out_free;
	default:
		free(t);
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		goto out_free;

	if (ed->policy->scap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE) {
		c = sprintf(s, "%s ", VAL_EVB_CAPA_RTE);
		if (c <= 0)
			goto out_free;
		s += c;
	}

	if (ed->policy->scap & LLDP_EVB_CAPABILITY_PROTOCOL_ECP) {
		c = sprintf(s, "%s ", VAL_EVB_CAPA_ECP);
		if (c <= 0)
			goto out_free;
		s += c;
	}

	if (ed->policy->scap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP) {
		c = sprintf(s, "%s ", VAL_EVB_CAPA_VDP);
		if (c <= 0)
			goto out_free;
		s += c;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(t), t);

	free(t);
	return cmd_success;

out_free:
	free(t);
	return cmd_invalid;
}

static int
_set_arg_capabilities(struct cmd *cmd, char *arg, const char *argvalue,
		      char *obuf, int obuf_len, bool test)
{
	u8 scap = 0;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);

	if (!ed)
		return cmd_invalid;

	if (strstr(argvalue, VAL_EVB_CAPA_RTE))
		scap |= LLDP_EVB_CAPABILITY_PROTOCOL_RTE;

	if (strstr(argvalue, VAL_EVB_CAPA_ECP))
		scap |= LLDP_EVB_CAPABILITY_PROTOCOL_ECP;

	if (strstr(argvalue, VAL_EVB_CAPA_VDP))
		scap |= LLDP_EVB_CAPABILITY_PROTOCOL_VDP;

	if (strstr(argvalue, VAL_EVB_CAPA_NONE))
		scap = 0;

	if (test)
		return cmd_success;

	ed->policy->scap = scap;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.capabilities",
		 TLVID_PREFIX, cmd->tlvid);

	if (set_cfg(ed->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING)) {
		printf("%s:%s: saving EVB capabilities failed.\n",
			__func__, ed->ifname);
		return cmd_invalid;
	}

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_capabilities(struct cmd *cmd, char *arg, char *argvalue,
				char *obuf, int obuf_len)
{
	return _set_arg_capabilities(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_arg_capabilities(struct cmd *cmd, char *arg, char *argvalue,
				 char *obuf, int obuf_len)
{
	return _set_arg_capabilities(cmd, arg, argvalue, obuf, obuf_len, true);
}

static int get_arg_rte(struct cmd *cmd, char *arg, char *argvalue,
		       char *obuf, int obuf_len)
{
	char s[EVB_BUF_SIZE];
	struct evb_data *ed;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;

	if (sprintf(s, "%i", ed->policy->rte) <= 0)
		return cmd_invalid;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(s), s);

	return cmd_success;
}

static int _set_arg_rte(struct cmd *cmd, char *arg, const char *argvalue,
			char *obuf, int obuf_len, bool test)
{
	int value, err;
	char arg_path[EVB_BUF_SIZE];
	struct evb_data *ed = NULL;

	if (cmd->cmd != cmd_settlv)
		goto out_err;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		goto out_err;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);

	if (!ed)
		return cmd_invalid;

	value = atoi(argvalue);

	if ((value < 0))
		goto out_err;

	if (test)
		return cmd_success;

	ed->policy->rte = value;

	err = snprintf(arg_path, sizeof(arg_path), "%s%08x.rte",
		       TLVID_PREFIX, cmd->tlvid);

	if (err < 0)
		goto out_err;

	if (err < 0)
		goto out_err;

	if (set_cfg(ed->ifname, cmd->type, arg_path, &argvalue,
		    CONFIG_TYPE_STRING))
		goto out_err;

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;

out_err:
	printf("%s:%s: saving EVB rte failed.\n", __func__, ed->ifname);
	return cmd_invalid;
}

static int set_arg_rte(struct cmd *cmd, char *arg, char *argvalue,
		       char *obuf, int obuf_len)
{
	return _set_arg_rte(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_arg_rte(struct cmd *cmd, char *arg, char *argvalue,
			char *obuf, int obuf_len)
{
	return _set_arg_rte(cmd, arg, argvalue, obuf, obuf_len, true);
}

static int get_arg_vsis(struct cmd *cmd, char *arg, char *argvalue,
			char *obuf, int obuf_len)
{
	char s[EVB_BUF_SIZE];
	struct evb_data *ed;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	ed = evb_data((char *) &cmd->ifname, cmd->type);
	if (!ed)
		return cmd_invalid;

	if (sprintf(s, "%04i", ed->policy->svsi) <= 0)
		return cmd_invalid;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg, (unsigned int) strlen(s), s);

	return cmd_success;
}

static int _set_arg_vsis(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, int obuf_len, bool test)
{
	int value, err;
	char arg_path[EVB_BUF_SIZE];
	char svalue[10];
	const char *sv;
	struct evb_data *ed = NULL;

	ed = evb_data((char *) &cmd->ifname, cmd->type);

	if (!ed)
		return cmd_invalid;

	if (cmd->cmd != cmd_settlv)
		goto out_err;

	switch (cmd->tlvid) {
	case (LLDP_MOD_EVB << 8) | LLDP_EVB_SUBTYPE:
		break;
	case INVALID_TLVID:
		goto out_err;
	default:
		return cmd_not_applicable;
	}

	value = atoi(argvalue);

	if ((value < 0) || (value > LLDP_EVB_DEFAULT_MAX_VSI))
		goto out_err;

	if (test)
		return cmd_success;

	ed->policy->svsi = value;

	err = snprintf(arg_path, sizeof(arg_path), "%s%08x.vsis",
		       TLVID_PREFIX, cmd->tlvid);

	if (err < 0)
		goto out_err;

	err = snprintf(svalue, sizeof(svalue), "%i", value);

	if (err < 0)
		goto out_err;

	sv = &svalue[0];

	if (set_cfg(ed->ifname, cmd->type, arg_path, &sv,
		    CONFIG_TYPE_STRING))
		goto out_err;

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;

out_err:
	printf("%s:%s: saving EVB vsis failed.\n", __func__, ed->ifname);
	return cmd_invalid;
}

static int set_arg_vsis(struct cmd *cmd, char *arg, char *argvalue,
			char *obuf, int obuf_len)
{
	return _set_arg_vsis(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_arg_vsis(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, int obuf_len)
{
	return _set_arg_vsis(cmd, arg, argvalue, obuf, obuf_len, true);
}

struct arg_handlers *evb_get_arg_handlers()
{
	return &arg_handlers[0];
}
