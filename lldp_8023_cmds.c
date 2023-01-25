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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_8023.h"
#include "lldp_mand_clif.h"
#include "lldp_8023_clif.h"
#include "lldp_8023_cmds.h"
#include "lldp/ports.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "lldp/states.h"

static int get_arg_add_frag_size(struct cmd *, char *, char *, char *, int);
static int set_arg_add_frag_size(struct cmd *, char *, char *, char *, int);
static int test_arg_add_frag_size(struct cmd *, char *, char *, char *, int);
static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int test_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
	{	.arg = ARG_8023_ADD_FRAG_SIZE, .arg_class = TLV_ARG,
		.handle_get = get_arg_add_frag_size,
		.handle_set = set_arg_add_frag_size,
		.handle_test = test_arg_add_frag_size, },
	{	.arg = ARG_TLVTXENABLE, .arg_class = TLV_ARG,
		.handle_get = get_arg_tlvtxenable,
		.handle_set = set_arg_tlvtxenable,
		.handle_test = test_arg_tlvtxenable, },
	{	.arg = 0 }
};

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
	case (LLDP_MOD_8023 << 8) | LLDP_8023_MACPHY_CONFIG_STATUS:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_POWER_VIA_MDI:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_LINK_AGGREGATION:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_MAXIMUM_FRAME_SIZE:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_ADD_ETH_CAPS:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (get_config_setting(cmd->ifname, cmd->type, arg_path,
				       &value, CONFIG_TYPE_BOOL))
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
	int value;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_8023 << 8) | LLDP_8023_MACPHY_CONFIG_STATUS:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_POWER_VIA_MDI:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_LINK_AGGREGATION:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_MAXIMUM_FRAME_SIZE:
	case (LLDP_MOD_8023 << 8) | LLDP_8023_ADD_ETH_CAPS:
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

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL))
		return cmd_failed;

	snprintf(obuf, obuf_len, "enableTx = %s\n", value ? "yes" : "no");
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

static int get_arg_add_frag_size(struct cmd *cmd, char *arg,
				 UNUSED char *argvalue, char *obuf,
				 int obuf_len)
{
	int add_frag_size, err;
	char arg_path[256];

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_8023 << 8) | LLDP_8023_ADD_ETH_CAPS:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);

	err = get_config_setting(cmd->ifname, cmd->type, arg_path,
				 &add_frag_size, CONFIG_TYPE_INT);

	if (!err)
		snprintf(obuf, obuf_len, "%02x%s%04x%i",
			 (unsigned int) strlen(arg), arg, 1, add_frag_size);
	else
		snprintf(obuf, obuf_len, "%02x%s%04d",
			 (unsigned int) strlen(arg), arg, 0);

	return cmd_success;
}

static int _set_arg_add_frag_size(struct cmd *cmd, char *arg, char *argvalue,
				  char *obuf, int obuf_len, bool test)
{
	char arg_path[256];
	int add_frag_size;
	unsigned long val;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (LLDP_MOD_8023 << 8) | LLDP_8023_ADD_ETH_CAPS:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	errno = 0;
	val = strtoul(argvalue, NULL, 0);
	if (errno || val >= 4)
		return cmd_invalid;

	add_frag_size = val;

	if (test)
		return cmd_success;

	snprintf(obuf, obuf_len, "%s = %d\n", arg, add_frag_size);

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);
	set_config_setting(cmd->ifname, cmd->type, arg_path, &add_frag_size,
			   CONFIG_TYPE_INT);
	printf("arg_path \"%s\"\n", arg_path);
	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int set_arg_add_frag_size(struct cmd *cmd, char *arg, char *argvalue,
				 char *obuf, int obuf_len)
{
	return _set_arg_add_frag_size(cmd, arg, argvalue, obuf, obuf_len,
				      false);
}

static int test_arg_add_frag_size(struct cmd *cmd, char *arg, char *argvalue,
				  char *obuf, int obuf_len)
{
	return _set_arg_add_frag_size(cmd, arg, argvalue, obuf, obuf_len,
				      true);
}

struct arg_handlers *ieee8023_get_arg_handlers()
{
	return &arg_handlers[0];
}
