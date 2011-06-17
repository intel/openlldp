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

#include <stdio.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_mand.h"
#include "lldp_mand_clif.h"
#include "lldp/ports.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldp/states.h"

static int get_arg_adminstatus(struct cmd *, char *, char *, char *);
static int set_arg_adminstatus(struct cmd *, char *, char *, char *);
static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *);
static int handle_get_arg(struct cmd *, char *, char *, char *);
static int handle_set_arg(struct cmd *, char *, char *, char *);

static struct arg_handlers arg_handlers[] = {
	{ ARG_ADMINSTATUS, get_arg_adminstatus, set_arg_adminstatus },
	{ ARG_TLVTXENABLE, get_arg_tlvtxenable, set_arg_tlvtxenable },
	{ NULL }
};

struct arg_handlers *mand_get_arg_handlers()
{
	return &arg_handlers[0];
}

int get_arg_adminstatus(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	int value;
	char *s;

	if (cmd->cmd != cmd_get_lldp)
		return cmd_bad_params;

	if (cmd->tlvid != INVALID_TLVID)
    		return cmd_bad_params;

	if (get_config_setting(cmd->ifname, arg, (void *)&value,
				CONFIG_TYPE_INT))
		value = disabled;

	switch (value) {
	case disabled:
		s = VAL_DISABLED;
		break;
	case enabledTxOnly:
		s = VAL_TX;
		break;
	case enabledRxOnly:
		s = VAL_RX;
		break;
	case enabledRxTx:
		s = VAL_RXTX;
		break;
	default:
		s = VAL_INVALID;
		return cmd_invalid;
	}
	
	sprintf(obuf, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		(unsigned int)strlen(s), s);
	return cmd_success;
}

int get_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	int value;
	char *s;

	if (cmd->cmd != cmd_gettlv)
		return cmd_bad_params;

	switch (cmd->tlvid) {
	case CHASSIS_ID_TLV:
	case PORT_ID_TLV:
	case TIME_TO_LIVE_TLV:
	case END_OF_LLDPDU_TLV:
		value = true;
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

int handle_get_arg(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval = cmd_invalid;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
			if (!strcasecmp(ah->arg, arg) && ah->handle_get) {
				rval = ah->handle_get(cmd, ah->arg, argvalue,
						      obuf);
				if (rval != cmd_not_applicable)
					return rval;
				else
					break;
			}
			ah++;
		}
	}
	return rval;
}

int set_arg_adminstatus(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	long value;

	if (cmd->cmd != cmd_set_lldp || cmd->tlvid != INVALID_TLVID)
		return cmd_bad_params;

	if (!strcasecmp(argvalue, VAL_RXTX))
		value =  enabledRxTx;
	else if (!strcasecmp(argvalue, VAL_RX))
		value = enabledRxOnly;
	else if (!strcasecmp(argvalue, VAL_TX))
		value = enabledTxOnly;
	else if (!strcasecmp(argvalue, VAL_DISABLED))
		value = disabled;
	else
		return cmd_invalid;  /* ignore invalid value */

	if (set_config_setting(cmd->ifname, arg, (void *)&value,
			       CONFIG_TYPE_INT)) {
		return cmd_failed;
	}

	set_lldp_port_admin(cmd->ifname, value);

	return cmd_success;
}

int set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	if (cmd->cmd != cmd_settlv)
		return cmd_bad_params;

	switch (cmd->tlvid) {
	case CHASSIS_ID_TLV:
	case PORT_ID_TLV:
	case TIME_TO_LIVE_TLV:
	case END_OF_LLDPDU_TLV:
		/* Cannot modify for Mandatory TLVs */
		return cmd_invalid;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}
}

int handle_set_arg(struct cmd *cmd, char *arg, char *argvalue, char *obuf)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval = cmd_success;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
			if (!strcasecmp(ah->arg, arg) && ah->handle_set) {
				rval = ah->handle_set(cmd, ah->arg, argvalue,
						      obuf);
				if (rval != cmd_not_applicable &&
				    rval != cmd_success)
					return rval;
				else
					break;
			}
			ah++;
		}
	}

	return cmd_success;
}


int get_tlvs(struct cmd *cmd, char *rbuf)
{
	u8 tlvs[2048];
	int size = 0;
	int i;
	u32 tlvid;
	int off = 0;
	int moff = 0;
	u16 type, len;

	if (cmd->ops & op_local) {
		if (get_local_tlvs(cmd->ifname, &tlvs[0], &size))
			return cmd_failed;
	} else if (cmd->ops & op_neighbor) {
		if (get_neighbor_tlvs(cmd->ifname, &tlvs[0], &size))
			return cmd_failed;
	} else
		return cmd_failed;

	/* filter down response if a specific TLVID was requested */
	if (cmd->tlvid != INVALID_TLVID) {
		/* step through PDU buffer and move matching TLVs to front */
		while (off < size) {
			type = *((u16 *) (tlvs+off));	
			type = htons(type);
			len = type & 0x01ff;
			type >>= 9;
			if (type < INVALID_TLVID) {
				tlvid = type;
			} else {
				tlvid = *((u32 *)(tlvs+off+2));	
				tlvid = ntohl(tlvid);
			}

			if (tlvid == cmd->tlvid) {
				memcpy(tlvs+moff, tlvs+off, sizeof(u16)+len);
				moff += sizeof(u16)+len;
			}

			off += (sizeof(u16)+len);
		}
		size = moff;
	}

	for (i = 0; i < size; i++) {
		sprintf(rbuf + 2*i, "%02x", tlvs[i]);
	}
	return cmd_success;
}

int get_port_stats(struct cmd *cmd, char *rbuf)
{
	int offset=0;
	struct portstats stats;

	if (get_lldp_port_statistics(cmd->ifname, &stats))
		return cmd_device_not_found;

	sprintf(rbuf+offset, "%08x", stats.statsFramesOutTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsFramesDiscardedTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsFramesInErrorsTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsFramesInTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsTLVsDiscardedTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsTLVsUnrecognizedTotal);
	offset+=8;
	sprintf(rbuf+offset, "%08x", stats.statsAgeoutsTotal);

	return cmd_success;
}

int mand_clif_cmd(void  *data,
		  struct sockaddr_un *from,
		  socklen_t fromlen,
		  char *ibuf, int ilen,
		  char *rbuf)
{
	struct cmd cmd;
	u8 len;
	u8 arglen;
	u16 argvalue_len;
	int ioff, roff;
	int rstatus = cmd_invalid;
	char *arg = NULL;
	char *argvalue = NULL;

	/* pull out the command elements of the command message */
	hexstr2bin(ibuf+CMD_CODE, (u8 *)&cmd.cmd, sizeof(cmd.cmd));
	hexstr2bin(ibuf+CMD_OPS, (u8 *)&cmd.ops, sizeof(cmd.ops));
	cmd.ops = ntohl(cmd.ops);
	hexstr2bin(ibuf+CMD_IF_LEN, &len, sizeof(len));
	ioff = CMD_IF;
	if (len < sizeof(cmd.ifname))
		memcpy(cmd.ifname, ibuf+CMD_IF, len);
	else
		return 1;

	cmd.ifname[len] = '\0';
	ioff += len;

	if (cmd.cmd == cmd_gettlv || cmd.cmd == cmd_settlv) {
		hexstr2bin(ibuf+ioff, (u8 *)&cmd.tlvid, sizeof(cmd.tlvid));
		cmd.tlvid = ntohl(cmd.tlvid);
		ioff += 2*sizeof(cmd.tlvid);
	} else {
		cmd.tlvid = INVALID_TLVID;
	}

	/* check for an arg and argvalue */
	if (ilen - ioff > 2*sizeof(arglen)) {
		hexstr2bin(ibuf+ioff, &arglen, sizeof(arglen));
		ioff += 2*sizeof(arglen);
		if (ilen - ioff >= arglen) {
			arg = ibuf+ioff;
			ioff += arglen;

			if (ilen - ioff > 2*sizeof(argvalue_len)) {
				hexstr2bin(ibuf+ioff, (u8 *)&argvalue_len,
					   sizeof(argvalue_len));
				argvalue_len = ntohs(argvalue_len);
				ioff += 2*sizeof(argvalue_len);
				if (ilen - ioff >= argvalue_len) {
					argvalue = ibuf+ioff;
					ioff += argvalue_len;
				}
			}
		}
	}

	if (arg)
		arg[arglen] = '\0';
	if (argvalue)
		argvalue[argvalue_len] = '\0';
	
	sprintf(rbuf, "%c%1x%02x%08x%02x%s", CMD_REQUEST, CLIF_MSG_VERSION,
		cmd.cmd, cmd.ops, (unsigned int)strlen(cmd.ifname), cmd.ifname);
	roff = strlen(rbuf);

	switch (cmd.cmd) {
	case cmd_getstats:
		if (arg || argvalue)
			break;
		rstatus = get_port_stats(&cmd, rbuf+roff);
		break;
	case cmd_gettlv:
		sprintf(rbuf+roff, "%08x", cmd.tlvid);
		roff+=8;
		if (argvalue)
			break;
		if (arg)
			rstatus = handle_get_arg(&cmd, arg, NULL,
						 rbuf+strlen(rbuf));
		else
			rstatus = get_tlvs(&cmd, rbuf+roff);
		break;
	case cmd_settlv:
		sprintf(rbuf+roff, "%08x", cmd.tlvid);
		roff+=8;
		if (arg && argvalue)
			rstatus = handle_set_arg(&cmd, arg, argvalue,
					 rbuf+strlen(rbuf));
		break;
	case cmd_get_lldp:
		if (argvalue)
			break;
		if (arg)
			rstatus = handle_get_arg(&cmd, arg, NULL,
					 rbuf+strlen(rbuf));
		break;
	case cmd_set_lldp:
		if (arg && argvalue)
			rstatus = handle_set_arg(&cmd, arg, argvalue,
				rbuf+strlen(rbuf));
		break;
	default:
		break;
	}

	return rstatus;
}
