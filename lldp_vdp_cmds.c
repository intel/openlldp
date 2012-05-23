/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens@linux.vnet.ibm.com>
  Author(s): Thomas Richter <tmricht@linux.vnet.ibm.com>

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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_vdp.h"
#include "lldp_mand_clif.h"
#include "lldp_vdp_clif.h"
#include "lldp_vdp_cmds.h"
#include "lldp/ports.h"
#include "messages.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "lldp/states.h"

static const char * const vsi_modes[] = {
	[VDP_MODE_PREASSOCIATE] = "VDP_MODE_PREASSOCIATED",
	[VDP_MODE_PREASSOCIATE_WITH_RR] = "VDP_MODE_PREASSOCIATED_WITH_RR",
	[VDP_MODE_ASSOCIATE] = "VDP_MODE_ASSOCIATED",
	[VDP_MODE_DEASSOCIATE] = "VDP_MODE_DEASSOCIATED",
};

static char *check_and_update(size_t *total, size_t *length, char *s, int c)
{
	if (c < 0)
		return NULL;
	*total += c;
	if ((unsigned)c >= *length)
		return NULL;
	*length -= c;
	return s + c;
}

char *print_profile(char *s, size_t length, struct vsi_profile *p)
{
	int c;
	size_t	total = 0;
	char *r = s;
	struct mac_vlan *mac_vlan;

	c = snprintf(s, length, "\nmode: %i (%s)\n",
			p->mode, vsi_modes[p->mode]);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "response: %i (%s)\n", p->response,
		     vdp_response2str(p->response));
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "state: %i (%s)\n",
		     p->state, vsi_states[p->state]);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "mgrid: %i\n", p->mgrid);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "id: %i (%#x)\n", p->id, p->id);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "version: %i\n", p->version);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	{
		char instance[INSTANCE_STRLEN + 2];

		instance2str(p->instance, instance, sizeof(instance));
		c = snprintf(s, length, "instance: %s\n", &instance[0]);
	}
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "format: %#x\n", p->format);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	c = snprintf(s, length, "entries: %u\n", p->entries);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	LIST_FOREACH(mac_vlan, &p->macvid_head, entry) {
		char macbuf[MAC_ADDR_STRLEN + 1];

		mac2str(mac_vlan->mac, macbuf, MAC_ADDR_STRLEN);
		c = snprintf(s, length, "mac: %s\n", macbuf);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;

		c = snprintf(s, length, "vlan: %i\n", mac_vlan->vlan);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;

		c = snprintf(s, length, "qos: %i\n", mac_vlan->qos);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;

		c = snprintf(s, length, "pid: %i\n", mac_vlan->req_pid);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;

		c = snprintf(s, length, "seq: %i\n", mac_vlan->req_seq);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;
	}

	return s;
}

static int
get_arg_tlvtxenable(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		    char *obuf, int obuf_len)
{
	int value;
	char *s;
	char arg_path[VDP_BUF_SIZE];

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
		snprintf(arg_path, sizeof(arg_path), "%s.%s", VDP_PREFIX, arg);

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

	snprintf(obuf, obuf_len, "%02zx%s%04zx%s",
		 strlen(arg), arg, strlen(s), s);

	return cmd_success;
}

static int _set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
				bool test)
{
	int value, err;
	char arg_path[VDP_BUF_SIZE];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
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

	snprintf(arg_path, sizeof(arg_path), "%s.%s", VDP_PREFIX, arg);

	err = set_cfg(cmd->ifname, cmd->type, arg_path,
		      &value, CONFIG_TYPE_BOOL);
	if (err)
		return cmd_failed;

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
	return _set_arg_tlvtxenable(cmd, arg, argvalue, true);
}

static int get_arg_mode(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			char *obuf, int obuf_len)
{
	char *s, *t;
	struct vsi_profile *np;
	struct vdp_data *vd;
	int count=0;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	vd = vdp_data(cmd->ifname);
	if (!vd) {
		LLDPAD_ERR("%s: vdp_data for %s not found !\n",
			    __func__, cmd->ifname);
		return cmd_invalid;
	}

	LIST_FOREACH(np, &vd->profile_head, profile)
		count++;

	s = t = malloc((count + 1) * VDP_BUF_SIZE);
	if (!s)
		return cmd_invalid;
	memset(s, 0, (count + 1) * VDP_BUF_SIZE);

	LIST_FOREACH(np, &vd->profile_head, profile)
		t = print_profile(t, (count + 1) * VDP_BUF_SIZE, np);

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(s), s);

	free(s);

	return cmd_success;
}

static void str2instance(struct vsi_profile *profile, char *buffer)
{
	unsigned int i, j = 0;

	for (i = 0; i <= strlen(buffer); i++) {
		if (buffer[i] == '-')
			continue;

		if (sscanf(&buffer[i], "%02hhx", &profile->instance[j]) == 1) {
			i++;
			j++;
		}
	}
}

/* INSTANCE_STRLEN = strlen("fa9b7fff-b0a0-4893-abcd-beef4ff18f8f") */
#define INSTANCE_STRLEN 36

int instance2str(const u8 *p, char *dst, size_t size)
{
	if (dst && size > INSTANCE_STRLEN) {
		snprintf(dst, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x"
			 "-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}

static void vdp_fill_profile(struct vsi_profile *profile, char *buffer,
			     int field)
{
	LLDPAD_DBG("%s: parsed %s\n", __func__, buffer);

	switch(field) {
		case MODE:
			profile->mode = atoi(buffer);
			break;
		case MGRID:
			profile->mgrid = atoi(buffer);
			break;
		case TYPEID:
			profile->id = atoi(buffer);
			break;
		case TYPEIDVERSION:
			profile->version = atoi(buffer);
			break;
		case INSTANCEID:
			str2instance(profile, buffer);
			break;
		case FORMAT:
			profile->format = atoi(buffer);
			break;
		default:
			LLDPAD_ERR("Unknown field in buffer !\n");
			break;
	}
}

static struct vsi_profile *vdp_parse_mode_line(char * argvalue)
{
	int field;
	char *cmdstring, *parsed;
	struct vsi_profile *profile;

	profile = vdp_alloc_profile();
	if (!profile)
		return NULL;

	cmdstring = strdup(argvalue);
	if (!cmdstring)
		goto out_free;

	field = 0;

	parsed = strtok(cmdstring, ",");

	while (parsed != NULL) {
		vdp_fill_profile(profile, parsed, field);
		field++;
		if (field > FORMAT)
			break;
		parsed = strtok(NULL, ",");
	}

	if ((field <= FORMAT) || (parsed == NULL))
		goto out_free;

	parsed = strtok(NULL, ",");

	while (parsed != NULL) {
		struct mac_vlan *mac_vlan;

		mac_vlan = calloc(1, sizeof(struct mac_vlan));
		if (mac_vlan == NULL)
			goto out_free;

		str2mac(parsed, &mac_vlan->mac[0], MAC_ADDR_LEN);

		parsed = strtok(NULL, ",");
		if (parsed == NULL) {
			free(mac_vlan);
			goto out_free;
		}

		mac_vlan->vlan = atoi(parsed);
		LIST_INSERT_HEAD(&profile->macvid_head, mac_vlan, entry);
		profile->entries++;
		parsed = strtok(NULL, ",");
	}

	free(cmdstring);
	return profile;

out_free:
	free(cmdstring);
	vdp_delete_profile(profile);
	return NULL;
}

static int _set_arg_mode(struct cmd *cmd, char *argvalue, bool test)
{
	struct vsi_profile *profile, *p;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	profile = vdp_parse_mode_line(argvalue);
	if (profile == NULL)
		return cmd_failed;

	profile->port = port_find_by_name(cmd->ifname);

	if (!profile->port) {
		vdp_delete_profile(profile);
		return cmd_invalid;
	}

	if (test) {
		vdp_delete_profile(profile);
		return cmd_success;
	}

	p = vdp_add_profile(profile);

	if (!p) {
		vdp_delete_profile(profile);
		return cmd_invalid;
	}

	if (profile != p)
		vdp_delete_profile(profile);

	return cmd_success;
}

static int set_arg_mode(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_mode(cmd, argvalue, false);
}

static int test_arg_mode(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			 UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_mode(cmd, argvalue, true);
}

static int get_arg_role(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			char *obuf, int obuf_len)
{
	struct vdp_data *vd;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
		vd = vdp_data(cmd->ifname);

		if (!vd) {
			LLDPAD_ERR("%s: could not find vdp_data for %s\n",
				    __FILE__, cmd->ifname);
			return cmd_invalid;
		}

		if (vd->role == VDP_ROLE_STATION)
			snprintf(obuf, obuf_len, "%02x%s%04x%s",
				 (unsigned int) strlen(arg), arg,
				 (unsigned int) strlen(VAL_STATION),
				 VAL_STATION);
		else if (vd->role == VDP_ROLE_BRIDGE)
			snprintf(obuf, obuf_len, "%02x%s%04x%s",
				 (unsigned int) strlen(arg), arg,
				 (unsigned int) strlen(VAL_BRIDGE), VAL_BRIDGE);
		else
			return cmd_failed;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	return cmd_success;
}

static int _set_arg_role(struct cmd *cmd, char *arg, char *argvalue, bool test)
{
	struct vdp_data *vd;
	char arg_path[VDP_BUF_SIZE];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	vd = vdp_data(cmd->ifname);

	if (!vd) {
		LLDPAD_ERR("%s: could not find vdp_data for %s\n",
			    __FILE__, cmd->ifname);
		return cmd_invalid;
	}

	if (!strcasecmp(argvalue, VAL_BRIDGE)) {
		if (!test)
			vd->role = VDP_ROLE_BRIDGE;
	} else if (!strcasecmp(argvalue, VAL_STATION)) {
		if (!test)
			vd->role = VDP_ROLE_STATION;
	} else {
		return cmd_invalid;
	}

	if (test)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s.%s", VDP_PREFIX, arg);

	const char *p = &argvalue[0];
	if (set_cfg(cmd->ifname, cmd->type, arg_path, &p, CONFIG_TYPE_STRING))
		return cmd_failed;

	return cmd_success;
}

static int set_arg_role(struct cmd *cmd, char *arg, char *argvalue,
			UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_role(cmd, arg, argvalue, false);
}

static int test_arg_role(struct cmd *cmd, char *arg, char *argvalue,
			 UNUSED char *obuf, UNUSED int obuf_len)
{
	return _set_arg_role(cmd, arg, argvalue, true);
}

static struct arg_handlers arg_handlers[] = {
	{
		.arg = ARG_VDP_MODE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_mode,
		.handle_set = set_arg_mode,
		.handle_test = test_arg_mode
	},
	{
		.arg = ARG_VDP_ROLE,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_role,
		.handle_set = set_arg_role,
		.handle_test = test_arg_role
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

struct arg_handlers *vdp_get_arg_handlers()
{
	return &arg_handlers[0];
}
