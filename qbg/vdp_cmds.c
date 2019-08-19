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
#include "qbg_vdp.h"
#include "lldp_mand_clif.h"
#include "qbg_vdp_cmds.h"
#include "qbg_utils.h"
#include "lldp/ports.h"
#include "lldp_tlv.h"
#include "messages.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "lldp/states.h"

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

static char *print_mode(char *s, size_t length, struct vsi_profile *p)
{
	int c;
	size_t	total = 0;
	char *r = s;
	struct mac_vlan *mac_vlan;
	char instance[VDP_UUID_STRLEN + 2];

	vdp_uuid2str(p->instance, instance, sizeof(instance));
	c = snprintf(s, length, "%d,%d,%d,%d,%s,%d",
		     p->state, p->mgrid, p->id, p->version, instance,
		     p->format);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		return r;

	LIST_FOREACH(mac_vlan, &p->macvid_head, entry) {
		char macbuf[MAC_ADDR_STRLEN + 1];

		mac2str(mac_vlan->mac, macbuf, MAC_ADDR_STRLEN);
		c = snprintf(s, length, ",%s,%d", macbuf, mac_vlan->vlan);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			return r;
	}
	return s;
}

static int vdp_cmdok(struct cmd *cmd, int expected)
{
	if (cmd->cmd != expected)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE:
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
	cmd_status good_cmd = vdp_cmdok(cmd, cmd_gettlv);
	int value;
	char *s;
	char arg_path[VDP_BUF_SIZE];

	if (good_cmd != cmd_success)
		return good_cmd;

	snprintf(arg_path, sizeof(arg_path), "%s.%s", VDP_PREFIX, arg);

	if (get_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL))
		value = false;

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
	cmd_status good_cmd = vdp_cmdok(cmd, cmd_settlv);
	int value, err;
	char arg_path[VDP_BUF_SIZE];

	if (good_cmd != cmd_success)
		return good_cmd;

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
	struct vsi_profile *np;
	struct vdp_data *vd;
	char mode_str[VDP_BUF_SIZE], *t = mode_str;
	int filled = 0;

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
		return cmd_device_not_found;
	}

	memset(mode_str, 0, sizeof mode_str);
	LIST_FOREACH(np, &vd->profile_head, profile) {
		t = print_mode(t, sizeof(mode_str) - filled, np);
		filled = t - mode_str;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(mode_str),
		 mode_str);
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

static struct vsi_profile *vdp_parse_mode_line(char *argvalue)
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

		if (str2mac(parsed, &mac_vlan->mac[0], MAC_ADDR_LEN)) {
			free(mac_vlan);
			goto out_free;
		}

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
	cmd_status good_cmd = vdp_cmdok(cmd, cmd_settlv);
	struct vsi_profile *profile, *p;
	struct vdp_data *vd;

	if (good_cmd != cmd_success)
		return good_cmd;

	profile = vdp_parse_mode_line(argvalue);
	if (profile == NULL)
		return cmd_failed;

	profile->port = port_find_by_ifindex(get_ifidx(cmd->ifname));

	if (!profile->port) {
		vdp_delete_profile(profile);
		return cmd_device_not_found;
	}

	vd = vdp_data(cmd->ifname);
	if (!vd) {
		vdp_delete_profile(profile);
		return cmd_device_not_found;
	}

	if (test) {
		vdp_delete_profile(profile);
		return cmd_success;
	}

	p = vdp_add_profile(vd, profile);
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
	cmd_status good_cmd = vdp_cmdok(cmd, cmd_gettlv);
	char arg_path[VDP_BUF_SIZE];
	const char *p;

	if (good_cmd != cmd_success)
		return good_cmd;

	snprintf(arg_path, sizeof(arg_path), "%s.%s", VDP_PREFIX, arg);
	if (get_cfg(cmd->ifname, cmd->type,
		    arg_path, &p, CONFIG_TYPE_STRING))
		p = VAL_STATION;

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg,
		 (unsigned int) strlen(p), p);

	return cmd_success;
}

static int _set_arg_role(struct cmd *cmd, char *arg, char *argvalue, bool test)
{
	cmd_status good_cmd = vdp_cmdok(cmd, cmd_settlv);
	struct vdp_data *vd;
	char arg_path[VDP_BUF_SIZE];

	if (good_cmd != cmd_success)
		return good_cmd;

	vd = vdp_data(cmd->ifname);

	if (!strcasecmp(argvalue, VAL_BRIDGE)) {
		if (!test && vd)
			vd->role = VDP_ROLE_BRIDGE;
	} else if (!strcasecmp(argvalue, VAL_STATION)) {
		if (!test && vd)
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

/*
 * Interface to build information for lldptool -V vdp
 */
struct tlv_info_vdp_nopp {	/* VSI information without profile data */
	u8 oui[3];		/* OUI */
	u8 sub;			/* Subtype */
	u8 role;		/* Role: station or bridge */
	u8 enabletx;
	u8 vdpbit_on;
}  __attribute__ ((__packed__));

/*
 * Flatten a profile stored as TLV and append it. Skip the first 4 bytes.
 * They contain the OUI already stored.
 * Returns the number of bytes added to the buffer.
 */
static int add_profile(unsigned char *pdu, size_t pdusz, struct vdp_data *vdp)
{
	size_t size = 0;

	if (!vdp->vdp)
		return size;
	size = (unsigned)TLVSIZE(vdp->vdp) - 4;
	if (pdusz >= size)
		memcpy(pdu, vdp->vdp->info + 4, size);
	else {
		LLDPAD_ERR("%s: %s buffer size too small (need %d bytes)\n",
			   __func__, vdp->ifname, TLVSIZE(vdp->vdp));
		return -1;
	}
	return size;
}

/*
 * Create unpacked VDP tlv for VSI profile when active.
 */
static int make_vdp_tlv(unsigned char *pdu, size_t pdusz, struct vdp_data *vdp)
{
	struct unpacked_tlv *tlv = (struct unpacked_tlv *)pdu;
	struct tlv_info_vdp_nopp *vdpno;
	size_t pduoff;
	int rc;

	tlv->info = (unsigned char *)(tlv + 1);
	vdpno = (struct tlv_info_vdp_nopp *)tlv->info;
	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(struct tlv_info_vdp_nopp);
	hton24(vdpno->oui, LLDP_MOD_VDP);
	vdpno->sub = LLDP_VDP_SUBTYPE;
	vdpno->role = vdp->role;
	vdpno->enabletx = vdp->enabletx;
	vdpno->vdpbit_on = vdp->vdpbit_on;
	pduoff = sizeof(*tlv) + tlv->length;
	pdusz -= pduoff;
	rc = add_profile(pdu + pduoff, pdusz - pduoff, vdp);
	if (rc > 0) {
		tlv->length += rc;
		rc = 0;
	}
	return rc;
}

/*
 * Flatten a VDP TLV into a byte stream.
 */
static int vdp_clif_profile(char *ifname, char *rbuf, size_t rlen)
{
	unsigned char pdu[VDP_BUF_SIZE];	/* Buffer for unpacked TLV */
	int i, c, rstatus = cmd_success;
	size_t sum  = 0;
	struct vdp_data *vd;
	struct unpacked_tlv *tlv = (struct unpacked_tlv *)pdu;
	struct packed_tlv *ptlv;

	LLDPAD_DBG("%s: %s rlen:%zu\n", __func__, ifname, rlen);
	vd = vdp_data(ifname);
	if (!vd)
		return cmd_device_not_found;

	if (make_vdp_tlv(pdu, sizeof pdu, vd))
		return cmd_failed;

	/* Convert to packed TLV */
	ptlv = pack_tlv(tlv);
	if (!ptlv)
		return cmd_failed;
	for (i = 0; i < TLVSIZE(tlv); ++i) {
		c = snprintf(rbuf, rlen, "%02x", ptlv->tlv[i]);
		rbuf = check_and_update(&sum, &rlen, rbuf, c);
		if (!rbuf) {
			rstatus = cmd_failed;
			break;
		}
	}
	free_pkd_tlv(ptlv);
	return rstatus;
}

/*
 * Module function to extract all VSI profile data on a given interface. It
 * is invoked via 'lldptool -t -i ethx -g ncb -V vdp' without any configuration
 * options.
 * This function does not support arguments and its values. They are handled
 * using the lldp_mand_cmds.c interfaces.
 */
int vdp_clif_cmd(char *ibuf, UNUSED int ilen, char *rbuf, int rlen)
{
	struct cmd cmd;
	u8 len, version;
	int c, ioff;
	size_t roff = 0, outlen = rlen;
	char *here;
	int rstatus = cmd_invalid;

	/* Pull out the command elements of the command message */
	hexstr2bin(ibuf + MSG_VER, (u8 *)&version, sizeof(u8));
	version >>= 4;
	hexstr2bin(ibuf + CMD_CODE, (u8 *)&cmd.cmd, sizeof(cmd.cmd));
	hexstr2bin(ibuf + CMD_OPS, (u8 *)&cmd.ops, sizeof(cmd.ops));
	cmd.ops = ntohl(cmd.ops);
	hexstr2bin(ibuf + CMD_IF_LEN, &len, sizeof(len));
	ioff = CMD_IF;
	if (len < sizeof(cmd.ifname))
		memcpy(cmd.ifname, ibuf + CMD_IF, len);
	else
		return cmd_failed;
	cmd.ifname[len] = '\0';
	ioff += len;

	memset(rbuf, 0, rlen);
	c = snprintf(rbuf, rlen, "%c%1x%02x%08x%02x%s",
		     CMD_REQUEST, CLIF_MSG_VERSION, cmd.cmd, cmd.ops,
		     (unsigned int)strlen(cmd.ifname), cmd.ifname);
	here = check_and_update(&roff, &outlen, rbuf, c);
	if (!here)
		return cmd_failed;

	if (version == CLIF_MSG_VERSION) {
		hexstr2bin(ibuf+ioff, &cmd.type, sizeof(cmd.type));
		ioff += 2 * sizeof(cmd.type);
	} else	/* Command valid only for nearest customer bridge */
		goto out;

	if (cmd.cmd == cmd_gettlv) {
		hexstr2bin(ibuf+ioff, (u8 *)&cmd.tlvid, sizeof(cmd.tlvid));
		cmd.tlvid = ntohl(cmd.tlvid);
		ioff += 2 * sizeof(cmd.tlvid);
	} else
		goto out;

	c = snprintf(here, outlen, "%08x", cmd.tlvid);
	here = check_and_update(&roff, &outlen, here, c);
	if (!here)
		return cmd_failed;
	rstatus = vdp_clif_profile(cmd.ifname, here, outlen);
out:
	return rstatus;
}
