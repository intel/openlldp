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

static int handle_get(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		      char *obuf, int obuf_len)
{
	struct arg_handlers *ah;
	int rval;
	char *nbuf;
	int nbuf_len;

	memset(obuf, 0, obuf_len);
	nbuf = obuf + 12;
	nbuf_len = obuf_len - 12;

	ah = get_my_arghndl(cmd->module_id);
	if (!ah)
		return cmd_not_applicable;
	for (; ah->arg; ++ah) {
		if (strcmp(ah->arg, ARG_VDP22_VSI))
			continue;
		if (ah->handle_get && (ah->arg_class == TLV_ARG)) {
			rval = ah->handle_get(cmd, ah->arg, argvalue,
					      nbuf, nbuf_len);
			if (rval != cmd_success && rval != cmd_not_applicable)
				return rval;

			nbuf_len -= strlen(nbuf);
			nbuf = nbuf + strlen(nbuf);
		}
	}
	return cmd_success;
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
 *           and op_local
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
 * -T (cmd_gettlv) -a assoc:
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
		   char *ibuf, int ilen, char *rbuf, int rlen)
{
	struct cmd cmd;
	u8 len, version;
	int ioff, roff;
	int rstatus = cmd_invalid;
	char **args;
	char **argvals;
	bool test_failed = false;
	int numargs = 0;
	int i, offset;

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

	if (!(cmd.ops & op_config))
		return cmd_invalid;

	/* Count args and argvalues */
	offset = ioff;
	for (numargs = 0; (ilen - offset) > 2; numargs++) {
		offset += 2;
		if (ilen - offset > 0) {
			offset++;
			if (ilen - offset > 4)
				offset += 4;
		}
	}

	args = calloc(numargs, sizeof(char *));
	if (!args)
		return cmd_failed;

	argvals = calloc(numargs, sizeof(char *));
	if (!argvals) {
		free(args);
		return cmd_failed;
	}

	if ((cmd.ops & op_arg) && (cmd.ops & op_argval))
		numargs = get_arg_val_list(ibuf, ilen, &ioff, args, argvals);
	else if (cmd.ops & op_arg)
		numargs = get_arg_list(ibuf, ilen, &ioff, args);

	snprintf(rbuf, rlen, "%c%1x%02x%08x%02x%s",
		 CMD_REQUEST, CLIF_MSG_VERSION,
		 cmd.cmd, cmd.ops,
		(unsigned int)strlen(cmd.ifname), cmd.ifname);
	roff = strlen(rbuf);

	/* Confirm port is a valid LLDP port */
	if (!get_ifidx(cmd.ifname) || !is_valid_lldp_device(cmd.ifname)) {
		free(argvals);
		free(args);
		return cmd_device_not_found;
	}

	snprintf(rbuf + roff, rlen - roff, "%08x", cmd.tlvid);
	roff += 8;
	if (cmd.cmd == cmd_gettlv) {
		if (!numargs)
			rstatus = handle_get(&cmd, NULL, NULL,
					     rbuf + strlen(rbuf),
					     rlen - strlen(rbuf));
		else
			for (i = 0; i < numargs; i++)
				rstatus = handle_get_arg(&cmd, args[i], NULL,
							 rbuf + strlen(rbuf),
							 rlen - strlen(rbuf));
	} else {
		for (i = 0; i < numargs; i++) {
			rstatus = handle_test_arg(&cmd, args[i], argvals[i],
						  rbuf + strlen(rbuf),
						  rlen - strlen(rbuf));
			if (rstatus != cmd_not_applicable &&
			    rstatus != cmd_success)
				test_failed = true;
		}
		if (!test_failed)
			for (i = 0; i < numargs; i++)
				rstatus = handle_set_arg(&cmd, args[i],
							 argvals[i],
							 rbuf + strlen(rbuf),
							 rlen - strlen(rbuf));
	}

	free(argvals);
	free(args);
	return rstatus;
}

/*
 * Trigger an event to an attached client.
 */
int vdp22_sendevent(struct vdpnl_vsi *p)
{
	char msg[MAX_CLIF_MSGBUF];

	vdp_vdpnl2str(p, msg, sizeof(msg));
	LLDPAD_DBG("%s:%s vsi:%p(%#2x), len:%zd msg:%s\n", __func__,
		   p->ifname, p, p->vsi_uuid[0], strlen(msg), msg);
	send_event(16, LLDP_MOD_VDP22, msg);
	return 0;
}

static int vdp22_cmdok(struct cmd *cmd, cmd_status expected)
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

static int set_arg_vsi3(struct cmd *cmd, char *argvalue, bool test, int size)
{
	cmd_status good_cmd = vdp22_cmdok(cmd, cmd_settlv);
	int rc;
	struct vdpnl_vsi vsi;
	struct vdpnl_mac mac[size];

	if (good_cmd != cmd_success)
		return good_cmd;

	memset(&vsi, 0, sizeof(vsi));
	memset(&mac, 0, sizeof(mac));
	vsi.maclist = mac;
	vsi.macsz = size;
	rc = vdp_str2vdpnl(argvalue, &vsi, cmd->ifname);
	if (rc) {
		good_cmd = cmd_bad_params;
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
	if (!rc)
		good_cmd = cmd_success;
	else if (rc == -ENODEV)
		good_cmd = cmd_device_not_found;
	else
		good_cmd = cmd_failed;
out:
	return good_cmd;
}

/*
 * Count the number of fid data fields in the argument value.
 */
#define	VDP22_FID_IDX	6		/* Min index of fid data */
static int count_fid(char *argvalue)
{
	char *p = argvalue;
	int i;

	for (i = 0; (p = strchr(p, ',')); ++i, ++p)
		;
	return i + 1 - VDP22_FID_IDX;
}

static int set_arg_vsi2(struct cmd *cmd, char *argvalue, bool test)
{
	int no = count_fid(argvalue);

	if (no <= 0)
		return -EINVAL;
	return set_arg_vsi3(cmd, argvalue, test, no);
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
	int rc, i;
	size_t used = 0;
	unsigned char wanted_req = vsi->request;

	for (i = 1; vdp22_status(i, vsi, 1) > 0; ++i) {
		if (wanted_req != vsi->request) {
			vdp22_freemaclist(vsi);
			continue;
		}
		rc = vdp_vdpnl2str(vsi, out + used, out_len - used);
		vdp22_freemaclist(vsi);
		if (rc) {
			strcat(out, ";");
			used = strlen(out);
		} else
			return 0;
	}
	return used;
}

/*
 * Return all VSIs on a particular interface into one string.
 */
static int get_arg_vsi(struct cmd *cmd, char *arg, UNUSED char *argvalue,
		       char *obuf, int obuf_len)
{
	cmd_status good_cmd = vdp22_cmdok(cmd, cmd_gettlv);
	struct vdpnl_vsi vsi;
	char vsi_str[MAX_CLIF_MSGBUF];
	int rc;

	if (good_cmd != cmd_success)
		return good_cmd;
	if (!port_find_by_ifindex(get_ifidx(cmd->ifname)))
		return cmd_device_not_found;
	good_cmd = ifok(cmd);
	if (good_cmd != cmd_success)
		return good_cmd;

	memset(obuf, 0, obuf_len);
	memset(&vsi, 0, sizeof(vsi));
	vsi.request = cmd->tlvid;
	strncpy(vsi.ifname, cmd->ifname, sizeof(vsi.ifname) - 1);
	good_cmd = cmd_failed;
	if (!catvsis(&vsi, vsi_str, sizeof(vsi_str)))
		goto out;
	rc = snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int)strlen(arg), arg, (unsigned int)strlen(vsi_str),
		 vsi_str);
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
