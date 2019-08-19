/*******************************************************************************

  Implementation of VDP 22 (ratified standard) according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2014

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

*******************************************************************************/

/*
 * Command line interface for vdp22 module. Handle argument parsing and
 * setting.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <errno.h>
#include <stdbool.h>

#include "lldp.h"
#include "lldpad.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "libconfig.h"
#include "config.h"
#include "messages.h"
#include "qbg22.h"
#include "qbg_vdp22def.h"
#include "qbg_vdp22.h"
#include "qbg_vdpnl.h"
#include "qbg_vdp22_cmds.h"
#include "qbg_vdp22_clif.h"

/*
 * Find module we are called for.
 */
static struct lldp_module *get_my_module(int thisid)
{
	struct lldp_module *np = NULL;

	LIST_FOREACH(np, &lldp_head, lldp)
		if (thisid == np->id)
			break;
	return np;
}

/*
 * Find argument handlers for module we are called for.
 */
static struct arg_handlers *get_my_arghndl(int thisid)
{
	struct lldp_module *np;
	struct arg_handlers *ah = NULL;

	np = get_my_module(thisid);
	if (np)
		if (np->ops && np->ops->get_arg_handler)
			ah = np->ops->get_arg_handler();
	return ah;
}

static int handle_get_arg(struct cmd *cmd, char *arg, char *argvalue,
			  char *obuf, int obuf_len)
{
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	ah = get_my_arghndl(cmd->module_id);
	if (!ah)
		return status;
	for (; ah->arg; ++ah) {
		if (!ah->handle_get)
			continue;
		if (!strncasecmp(ah->arg, arg, strlen(ah->arg))) {
			rval = ah->handle_get(cmd, arg, argvalue,
					      obuf, obuf_len);
			if (rval != cmd_success &&
			    rval != cmd_not_applicable)
				return rval;
			else if (rval == cmd_success)
				status = rval;
			break;
		}
	}
	return status;
}

static int handle_test_arg(struct cmd *cmd, char *arg, char *argvalue,
			   char *obuf, int obuf_len)
{
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	ah = get_my_arghndl(cmd->module_id);
	if (!ah)
		return status;
	for (; ah->arg; ++ah) {
		if (!strcasecmp(ah->arg, arg) && ah->handle_test) {
			rval = ah->handle_test(cmd, ah->arg, argvalue,
					      obuf, obuf_len);
			if (rval != cmd_not_applicable &&
			    rval != cmd_success)
				return rval;
			else if (rval == cmd_success)
				status = rval;
			break;
		}
	}
	return status;
}

static int handle_set_arg(struct cmd *cmd, char *arg, char *argvalue,
			  char *obuf, int obuf_len)
{
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	ah = get_my_arghndl(cmd->module_id);
	if (!ah)
		return status;
	for (; ah->arg; ++ah) {
		if (!strcasecmp(ah->arg, arg) && ah->handle_set) {
			rval = ah->handle_set(cmd, ah->arg, argvalue,
					      obuf, obuf_len);
			if (rval != cmd_not_applicable &&
			    rval != cmd_success)
				return rval;
			else if (rval == cmd_success)
				status = rval;
			break;
		}
	}
	return status;
}

/*
 * Interface function called from attached client. This client can receive
 * events from lldpad.
 *
 * The command string has the following format in ascii:
 * M000080c4C3020000001c05veth0020080c40003vsi004btext
 *  aaaaaaaabbccddddddddeefffffgghhhhhhhhiijjjkkkkllll
 *
 * with
 * aaaaaaaa: 8 hex digits module identifier (which has been stripped already)
 * bb:  C for command and 2 or 3 for message version number
 * cc: 1 for get command and 2 for set command
 * dddddddd: 8 hex digits options, supported are op_arg, op_argval, op_conifg
 *           and op_local. The number of filter (fid) parameters are encoded
 *           here (second byte from right).
 * ee: 2 hex digit length of interface name
 * ffff: string for interface name
 * gg: 2 hex digit for bridge type (nearest customer bridge only)
 * hhhhhhhh: 8 hex digit TLV identifier
 * ii: 2 hex digit length of argument name
 * jjj: string for argument name
 * kkkk: 4 hex digits for length of argument value
 * llll: argument value
 *
 * Note the kkkk and llll fields may show up more than once. It depends.
 * The total input length can be used to determine the number of arguaments.
 *
 * The member ops of struct cmd settings depends on the invoked with
 * -T (cmd_getvsi) -a assoc:
 * -c key      --> ops=(0x15) op_config,op_arg,op_local), numargs > 0
 * -c key=abc  --> ops=(0x1d) op_config,op_arg,op_argval,op_local), numargs > 0
 * -c          --> ops=0x11 (op_config,op_local), numargs = 0
 * without -c --> ops=0x1 (op_local), numargs = 0
 *
 * Without flag op_config being set invoke a function which retrieves all
 * TLVs for pretty printing. This is currently not supported.
 *
 * With flag op_config being set return all currently active VSI associations.
 */
int vdp22_clif_cmd(UNUSED void *data, UNUSED struct sockaddr_un *from,
		   UNUSED socklen_t fromlen,
		   char *ibuf, UNUSED int ilen, char *rbuf, int rlen)
{
	struct cmd cmd;
	u8 len, version;
	int ioff, roff;
	int rstatus = cmd_invalid;
	bool test_failed = false;

	memset(&cmd, 0, sizeof(cmd));
	cmd.module_id = LLDP_MOD_VDP22;
	/* Pull out the command elements of the command message */
	hexstr2bin(ibuf + MSG_VER, (u8 *)&version, sizeof(u8));
	version = version >> 4;
	hexstr2bin(ibuf + CMD_CODE, (u8 *)&cmd.cmd, sizeof(cmd.cmd));
	hexstr2bin(ibuf + CMD_OPS, (u8 *)&cmd.ops, sizeof(cmd.ops));
	cmd.ops = ntohl(cmd.ops);
	hexstr2bin(ibuf + CMD_IF_LEN, &len, sizeof(len));
	ioff = CMD_IF;
	if (len < sizeof(cmd.ifname))
		memcpy(cmd.ifname, ibuf+CMD_IF, len);
	else
		return rstatus;

	cmd.ifname[len] = '\0';
	ioff += len;

	if (version == CLIF_MSG_VERSION) {
		hexstr2bin(ibuf+ioff, &cmd.type, sizeof(cmd.type));
		ioff += 2 * sizeof(cmd.type);
	} else {
		return cmd_not_applicable;
	}

	if (cmd.cmd == cmd_gettlv || cmd.cmd == cmd_settlv) {
		hexstr2bin(ibuf + ioff, (u8 *)&cmd.tlvid, sizeof(cmd.tlvid));
		cmd.tlvid = ntohl(cmd.tlvid);
		ioff += 2 * sizeof(cmd.tlvid);
		if (cmd.tlvid != VDP22_ASSOC && cmd.tlvid != VDP22_DEASSOC
		    && cmd.tlvid != VDP22_PREASSOC
		    && cmd.tlvid != VDP22_PREASSOC_WITH_RR)
			return cmd_invalid;
	} else {
		return cmd_not_applicable;
	}

	if (!(cmd.ops & op_config) && (cmd.cmd != cmd_gettlv))
		return cmd_invalid;

	snprintf(rbuf, rlen, "%c%1x%02x%08x%02x%s",
		 CMD_REQUEST, CLIF_MSG_VERSION,
		 cmd.cmd, cmd.ops,
		(unsigned int)strlen(cmd.ifname), cmd.ifname);
	roff = strlen(rbuf);

	/* Confirm port is a valid LLDP port */
	if (!get_ifidx(cmd.ifname) || !is_valid_lldp_device(cmd.ifname)) {
		return cmd_device_not_found;
	}

	snprintf(rbuf + roff, rlen - roff, "%08x", cmd.tlvid);
	roff += 8;
	if (cmd.cmd == cmd_gettlv) {
		rstatus = handle_get_arg(&cmd, ARG_VDP22_VSI, ibuf + ioff,
					 rbuf + strlen(rbuf),
					 rlen - strlen(rbuf));
	} else {
		rstatus = handle_test_arg(&cmd, ARG_VDP22_VSI,
						ibuf + ioff,
						rbuf + strlen(rbuf),
						rlen - strlen(rbuf));
		if (rstatus != cmd_not_applicable && rstatus != cmd_success)
			test_failed = true;
		if (!test_failed)
			rstatus = handle_set_arg(&cmd,
						ARG_VDP22_VSI, ibuf + ioff,
						rbuf + strlen(rbuf),
						rlen - strlen(rbuf));
	}
	return rstatus;
}

/*
 * Trigger an event to an attached client.
 */
int vdp22_sendevent(struct vdpnl_vsi *p)
{
	char msg[MAX_CLIF_MSGBUF];
	char tmp_buf[MAX_CLIF_MSGBUF];
	int c, len;

	vdp_vdpnl2str(p, tmp_buf, sizeof(msg));
	len = strlen(tmp_buf);
	if ((unsigned)len > sizeof(msg))
		return 0;
	c = snprintf(msg, sizeof(msg), "%04x%s", len, tmp_buf);
	if ((c < 0) || ((unsigned)c >= sizeof(msg)))
		return 0;
	LLDPAD_DBG("%s:%s vsi:%p(%#2x), len:%zd msg:%s\n", __func__,
		   p->ifname, p, p->vsi_uuid[0], strlen(msg), msg);
	send_event(16, LLDP_MOD_VDP22, msg);
	return 0;
}

static int vdp22_cmdok(struct cmd *cmd, int expected)
{
	if (cmd->cmd != expected)
		return cmd_invalid;

	switch (cmd->module_id) {
	case LLDP_MOD_VDP22:
		if (cmd->type != NEAREST_CUSTOMER_BRIDGE)
			return cmd_agent_not_supported;

		return cmd_success;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}
}

/*
 * Test if role is station and VDP protocol supported for this interface.
 * Needed to enable testing of possible command failure.
 */
static int ifok(struct cmd *cmd)
{
	cmd_status good_cmd = cmd_success;

	switch (vdp22_info(cmd->ifname)) {
	case -ENODEV:
		good_cmd = cmd_device_not_found;
		break;
	case -EOPNOTSUPP:
		good_cmd = cmd_not_applicable;
		break;
	}
	return good_cmd;
}

static int get_vdp22_retval(int rc)
{
	if (!rc)
		return cmd_success;

	switch (rc) {
	case -EPROTONOSUPPORT:
		return cmd_vdp_prot_no_support;
	case -EOPNOTSUPP:
		return cmd_not_capable;
	case -EINVAL:
		return cmd_bad_params;
	case -ENOMEM:
		return cmd_vdp_nomem;
	case -EBUSY:
		return cmd_vdp_busy;
	case -ENODEV:
		return cmd_device_not_found;
	default:
		return cmd_failed;
	}
}

static int set_arg_vsi3(struct cmd *cmd, char *argvalue, bool test, int size,
			int oui_size)
{
	cmd_status good_cmd = vdp22_cmdok(cmd, cmd_settlv);
	int rc;
	struct vdpnl_vsi vsi;
	struct vdpnl_mac mac[size];
	struct vdpnl_oui_data_s oui[oui_size];

	if (good_cmd != cmd_success)
		return good_cmd;

	memset(&vsi, 0, sizeof(vsi));
	memset(&mac, 0, sizeof(mac));
	memset(&oui, 0, sizeof(oui));
	vsi.maclist = mac;
	vsi.macsz = size;
	vsi.oui_list = (struct vdpnl_oui_data_s *)oui;
	vsi.ouisz = oui_size;
	rc = vdp_str2vdpnl(argvalue, &vsi, cmd->ifname);
	if (rc) {
		good_cmd = get_vdp22_retval(rc);
		goto out;
	}
	if (!port_find_by_ifindex(get_ifidx(cmd->ifname))) {
		good_cmd = cmd_device_not_found;
		goto out;
	}
	good_cmd = ifok(cmd);
	if (good_cmd != cmd_success || test)
		goto out;
	rc = vdp22_request(&vsi, 1);
	good_cmd = get_vdp22_retval(rc);

out:
	return good_cmd;
}

static int set_arg_vsi2(struct cmd *cmd, char *argvalue, bool test)
{
	int no = (cmd->ops >> OP_FID_POS) & 0xff;
	int oui_no = (cmd->ops >> OP_OUI_POS) & 0xff;

	if (no <= 0)
		return -EINVAL;
	if ((cmd->ops & op_arg) && (cmd->ops & op_argval))
		return set_arg_vsi3(cmd, argvalue, test, no, oui_no);
	else /* Not supported for now */
		return cmd_failed;
}

static int set_arg_vsi(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			UNUSED char *obuf, UNUSED int obuf_len)
{
	return set_arg_vsi2(cmd, argvalue, false);
}

static int test_arg_vsi(struct cmd *cmd, UNUSED char *arg, char *argvalue,
			 UNUSED char *obuf, UNUSED int obuf_len)
{
	return set_arg_vsi2(cmd, argvalue, true);
}

/*
 * Concatenate all VSI information into one string.
 * Return length of string in bytes.
 */
static int catvsis(struct vdpnl_vsi *vsi, char *out, size_t out_len)
{
	int rc, i, len, c;
	size_t used = 0;
	unsigned char wanted_req = vsi->request;
	char tmp_buf[MAX_CLIF_MSGBUF];

	memset(tmp_buf, 0, sizeof(tmp_buf));
	for (i = 1; vdp22_status(i, vsi, 1) > 0; ++i) {
		if (wanted_req != vsi->request) {
			vdp22_freemaclist(vsi);
			vsinl_delete_oui(vsi);
			continue;
		}
		rc = vdp_vdpnl2str(vsi, tmp_buf, out_len - used);
		len = strlen(tmp_buf);
		c = snprintf(out + used, out_len - used, "%04x%s", len,
			     tmp_buf);
		if ((c < 0) || ((unsigned)c >= (out_len - used)))
			return 0;
		vdp22_freemaclist(vsi);
		vsinl_delete_oui(vsi);
		if (rc) {
			used = strlen(out);
		} else
			return 0;
	}
	return used;
}

/*
 * Based on the VSI arguments specified, checks if it matches.
 * This does't check for all VSI parameters.
 */

static bool vdp22_partial_vsi_equal(struct vsi22 *p1, struct vsi22 *p2,
				    enum vsi_key_arg vsi_arg_key_flags)
{
	enum vsi_key_arg key_enum;

	for (key_enum = VSI_MODE_ARG; key_enum < VSI_INVALID_ARG; key_enum++) {
		if (!((1 << key_enum) & vsi_arg_key_flags))
			continue;
		switch (key_enum) {
		case VSI_MODE_ARG:
			break;
		case VSI_MGRID2_ARG:
			if (memcmp(p1->mgrid, p2->mgrid,
				   sizeof(p2->mgrid)))
				return false;
			/* FALLTHROUGH */
		case VSI_TYPEID_ARG:
			if (p1->type_id != p2->type_id)
				return false;
			break;
		case VSI_TYPEIDVER_ARG:
			if (p1->type_ver != p2->type_ver)
				return false;
			break;
#ifdef LATER
/* Currently not supported */
		case VSI_VSIIDFRMT_ARG:
			if (p1->vsi_fmt != p2->vsi_fmt)
				return false;
			break;
#endif
		case VSI_VSIID_ARG:
			if (memcmp(p1->vsi, p2->vsi, sizeof(p1->vsi)))
				return false;
			break;
		case VSI_FILTER_ARG:
			if ((p1->fif != p2->fif) || (!vdp22_cmp_fdata(p1, p2)))
				return false;
			break;
		case VSI_HINTS_ARG:
			break;
		default:
			return false;
		}
	}
	return true;
}

static int get_vsi_partial_arg(UNUSED char *arg, char *orig_argvalue,
			       struct vdpnl_vsi *vsinl, char *out,
			       size_t out_len)
{
	char tmp_buf[MAX_CLIF_MSGBUF];
	struct vsi22 *p, *vsi;
	struct vdp22 *vdp;
	size_t used = 0;
	int rc = -ENOMEM, len, c;
	u16 vsi_arg_key_flags = 0;

	rc = vdp22_parse_str_vdpnl(vsinl, &vsi_arg_key_flags, orig_argvalue);
	if (rc)
		goto out;
	vdp = vdp22_getvdp(vsinl->ifname);
	if (!vdp)
		goto out;

	vsi = vdp22_alloc_vsi_ext(vsinl, &rc);
	if (!vsi)
		goto out;
	LIST_FOREACH(p, &vdp->vsi22_que, node) {
		if (p->vsi_mode != vsi->vsi_mode)
			continue;
		if (vdp22_partial_vsi_equal(p, vsi, vsi_arg_key_flags)) {
			copy_vsi_external(vsinl, p, 1);
			rc = vdp_vdpnl2str(vsinl, tmp_buf, out_len - used);
			len = strlen(tmp_buf);
			c = snprintf(out + used, out_len - used, "%04x%s",
				     len, tmp_buf);
			vdp22_freemaclist(vsinl);
			vsinl_delete_oui(vsinl);
			if ((c < 0) || ((unsigned)c >= (out_len - used)))
				goto out_delvsi;
			if (rc)
				used = strlen(out);
			else
				goto out_delvsi;
		}
	}
out_delvsi:
	vdp22_delete_vsi(vsi);
out:
	return rc;
}

/*
 * Return all VSIs on a particular interface into one string.
 */
static int get_arg_vsi(struct cmd *cmd, char *arg, char *argvalue,
		       char *obuf, int obuf_len)
{
	cmd_status good_cmd = vdp22_cmdok(cmd, cmd_gettlv);
	struct vdpnl_vsi vsi;
	char vsi_str[MAX_CLIF_MSGBUF];
	int rc;
	int fsize = (cmd->ops >> OP_FID_POS) & 0xff;
	struct vdpnl_mac mac[fsize];

	if (good_cmd != cmd_success)
		return good_cmd;
	if (!port_find_by_ifindex(get_ifidx(cmd->ifname)))
		return cmd_device_not_found;
	good_cmd = ifok(cmd);
	if (good_cmd != cmd_success)
		return good_cmd;

	memset(obuf, 0, obuf_len);
	memset(&vsi, 0, sizeof(vsi));
	memset(vsi_str, 0, sizeof(vsi_str));
	vsi.request = cmd->tlvid;
	strncpy(vsi.ifname, cmd->ifname, sizeof(vsi.ifname));
	good_cmd = cmd_failed;
	if ((cmd->ops & op_config) && (cmd->ops & op_arg)) {
		memset(&mac, 0, sizeof(mac));
		vsi.macsz = fsize;
		vsi.maclist = mac;
		rc = get_vsi_partial_arg(arg, argvalue, &vsi, vsi_str,
					 sizeof(vsi_str));
	} else
		rc = catvsis(&vsi, vsi_str, sizeof(vsi_str));
	if (!rc) {
		good_cmd = get_vdp22_retval(rc);
		goto out;
	}
	rc = snprintf(obuf, obuf_len, "%s", vsi_str);
	if (rc > 0 || rc < obuf_len)
		good_cmd = cmd_success;
out:
	return good_cmd;
}


static struct arg_handlers arg_handlers[] = {
	{
		.arg = ARG_VDP22_VSI,
		.arg_class = TLV_ARG,
		.handle_get = get_arg_vsi,
		.handle_set = set_arg_vsi,
		.handle_test = test_arg_vsi
	},
	{
		.arg = 0
	}
};

struct arg_handlers *vdp22_arg_handlers()
{
	return &arg_handlers[0];
}
