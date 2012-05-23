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
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_med.h"
#include "lldp_8023.h"
#include "lldp_mand_clif.h"
#include "lldp_med_clif.h"
#include "lldp/ports.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "lldp/states.h"

static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int test_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int get_arg_med_devtype(struct cmd *, char *, char *, char *, int);
static int set_arg_med_devtype(struct cmd *, char *, char *, char *, int);
static int test_arg_med_devtype(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
	{	.arg = ARG_TLVTXENABLE, .arg_class = TLV_ARG,
		.handle_get = get_arg_tlvtxenable,
		.handle_set = set_arg_tlvtxenable,
		.handle_test = test_arg_tlvtxenable, },
	{	.arg = ARG_MED_DEVTYPE, .arg_class = TLV_ARG,
		.handle_get = get_arg_med_devtype,
		.handle_set = set_arg_med_devtype,
		.handle_test = test_arg_med_devtype, },
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
	case (OUI_TIA_TR41 << 8):
	case (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID:
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

	snprintf(obuf, obuf_len, "%02zx%s%04zx%s",
		strlen(arg), arg, strlen(s), s);

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
	case (OUI_TIA_TR41 << 8):
	case (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID:
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

	if (set_config_setting(cmd->ifname, cmd->type, arg_path,
			       &value, CONFIG_TYPE_BOOL))
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

static int
get_arg_med_devtype(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		    char *obuf, int obuf_len)
{
	long value;
	char *s;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_TIA_TR41 << 8):
		value = get_med_devtype(cmd->ifname, cmd->type);
		break;
	case (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID:
		return cmd_not_applicable;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	switch (value) {
	case LLDP_MED_DEVTYPE_NOT_DEFINED:
		s = VAL_MED_NOT;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
		s = VAL_MED_CLASS_I;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
		s = VAL_MED_CLASS_II;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
		s = VAL_MED_CLASS_III;
		break;
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		s = VAL_MED_NETCON;
		break;
	default:
		return cmd_failed;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		(unsigned int)strlen(s), s);

	return cmd_success;
}

static int _set_arg_med_devtype(struct cmd *cmd, char *argvalue,
			       char *obuf, int obuf_len, bool test)
{
	long value;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_TIA_TR41 << 8):
		break;
	case (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME:
	case (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID:
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	if (!strcasecmp(argvalue, VAL_MED_NOT))
		value = LLDP_MED_DEVTYPE_NOT_DEFINED;

	else if (!strcasecmp(argvalue, VAL_MED_CLASS_I))
		value = LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I;

	else if (!strcasecmp(argvalue, VAL_MED_CLASS_II))
		value = LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II;

	else if (!strcasecmp(argvalue, VAL_MED_CLASS_III))
		value = LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III;

	else if (!strcasecmp(argvalue, VAL_MED_NETCON))
		value = LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY;
	else
		return cmd_invalid;

	if (test)
		return cmd_success;

	set_med_devtype(cmd->ifname, cmd->type, value);

	/* set up default enabletx values based on class type */
	switch (value) {
	case LLDP_MED_DEVTYPE_NOT_DEFINED:
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_RESERVED);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME);
		tlv_disabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID);
		break;

	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY);
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_RESERVED);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME);
		tlv_enabletx(cmd->ifname, cmd->type, (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID);
		tlv_enabletx(cmd->ifname, cmd->type, SYSTEM_CAPABILITIES_TLV);
		tlv_enabletx(cmd->ifname, cmd->type, (LLDP_MOD_8023 << 8) | LLDP_8023_MACPHY_CONFIG_STATUS);
		break;
	default:
		return cmd_failed;
	}

	snprintf(obuf, obuf_len, "devtype = %li\n", value);

	somethingChangedLocal(cmd->ifname, cmd->type);

	return cmd_success;
}

static int
set_arg_med_devtype(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		    char *obuf, int obuf_len)
{
	return _set_arg_med_devtype(cmd, argvalue, obuf, obuf_len, false);
}

static int
test_arg_med_devtype(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		     char *obuf, int obuf_len)
{
	return _set_arg_med_devtype(cmd, argvalue, obuf, obuf_len, true);
}

struct arg_handlers *med_get_arg_handlers()
{
	return &arg_handlers[0];
}
