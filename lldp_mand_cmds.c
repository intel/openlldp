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
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include "lldpad.h"
#include "ctrl_iface.h"
#include "lldp.h"
#include "lldp_tlv.h"
#include "lldp_mand.h"
#include "lldp_mand_clif.h"
#include "lldp/ports.h"
#include "libconfig.h"
#include "config.h"
#include "clif_msgs.h"
#include "lldpad_status.h"
#include "lldp/states.h"
#include "lldp_util.h"
#include "messages.h"

static int get_arg_adminstatus(struct cmd *, char *, char *, char *, int);
static int set_arg_adminstatus(struct cmd *, char *, char *, char *, int);
static int test_arg_adminstatus(struct cmd *, char *, char *, char *, int);
static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int handle_get_arg(struct cmd *, char *, char *, char *, int);
static int handle_set_arg(struct cmd *, char *, char *, char *, int);
static int handle_test_arg(struct cmd *, char *, char *, char *, int);

static int get_mand_subtype(struct cmd *, char *, char *, char *, int);
static int set_mand_subtype(struct cmd *, char *, char *, char *, int);
static int test_mand_subtype(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
	{	.arg = ARG_ADMINSTATUS, .arg_class = LLDP_ARG,
		.handle_get = get_arg_adminstatus,
		.handle_set = set_arg_adminstatus,
		.handle_test = test_arg_adminstatus, },
	{	.arg = ARG_TLVTXENABLE, .arg_class = TLV_ARG,
		.handle_get = get_arg_tlvtxenable,
		.handle_set = set_arg_tlvtxenable,
		.handle_test = set_arg_tlvtxenable, },
	{	.arg = ARG_MAND_SUBTYPE,
		.arg_class = TLV_ARG,
		.handle_get = get_mand_subtype,
		.handle_set = set_mand_subtype,
		.handle_test = test_mand_subtype, },
	{	.arg = 0 }
};

static int get_mand_subtype(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			    char *obuf, int obuf_len)
{
	int subtype;
	char *string, arg_path[256];

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case CHASSIS_ID_TLV:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, TLVID_NOUI(CHASSIS_ID_TLV),
			 ARG_MAND_SUBTYPE);
		get_config_setting(cmd->ifname, cmd->type, arg_path,
				   &subtype, CONFIG_TYPE_INT);

		switch (subtype) {
		case CHASSIS_ID_CHASSIS_COMPONENT:
			string = "CHASSIS_ID_CHASSIS_COMPONENT";
			break;
		case CHASSIS_ID_INTERFACE_ALIAS:
			string = "CHASSIS_ID_INTERFACE_ALIAS";
			break;
		case CHASSIS_ID_PORT_COMPONENT:
			string = "CHASSIS_ID_PORT_COMPONENT";
			break;
		case CHASSIS_ID_MAC_ADDRESS:
			string = "CHASSIS_ID_MAC_ADDRESS";
			break;
		case CHASSIS_ID_NETWORK_ADDRESS:
			string = "CHASSIS_ID_NETWORK_ADDRESS";
			break;
		case CHASSIS_ID_INTERFACE_NAME:
			string = "CHASSIS_ID_INTERFACE_NAME";
			break;
		case CHASSIS_ID_LOCALLY_ASSIGNED:
			string = "CHASSIS_ID_LOCALLY_ASSIGNED";
			break;
		default:
			string = "DEFAULT";
			break;
		}
		break;
	case PORT_ID_TLV:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, TLVID_NOUI(PORT_ID_TLV),
			 ARG_MAND_SUBTYPE);
		get_config_setting(cmd->ifname, cmd->type, arg_path,
				   &subtype, CONFIG_TYPE_INT);

		switch (subtype) {
		case PORT_ID_INTERFACE_ALIAS:
			string = "PORT_ID_INTERFACE_ALIAS";
			break;
		case PORT_ID_PORT_COMPONENT:
			string = "PORT_ID_PORT_COMPONENT";
			break;
		case PORT_ID_MAC_ADDRESS:
			string = "PORT_ID_MAC_ADDRESS";
			break;
		case PORT_ID_NETWORK_ADDRESS:
			string = "PORT_ID_NETWORK_ADDRESS";
			break;
		case PORT_ID_INTERFACE_NAME:
			string = "PORT_ID_INTERFACE_NAME";
			break;
		case PORT_ID_AGENT_CIRCUIT_ID:
			string = "PORT_ID_AGENT_CIRCUIT_ID";
			break;
		case PORT_ID_LOCALLY_ASSIGNED:
			string = "PORT_ID_LOCALLY_ASSIGNED";
			break;
		default:
			string = "DEFAULT";
			break;
		}
		break;
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	snprintf(obuf, obuf_len, "%02x%s%04x%s",
		 (unsigned int) strlen(arg), arg,
		 (unsigned int)strlen(string), string);
	return 0;
}

static int _set_mand_subtype(struct cmd *cmd, char *arg, char *argvalue,
			     char *obuf, int obuf_len, bool test)
{
	struct mand_data *md;
	int subtype;
	char *end;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	md = mand_data(cmd->ifname, cmd->type);

	switch (cmd->tlvid) {
	case CHASSIS_ID_TLV:
		break;
	case PORT_ID_TLV:
		break;
	case INVALID_TLVID:
		return cmd_invalid;
	default:
		return cmd_not_applicable;
	}

	errno = 0;
	subtype = strtoul(argvalue, &end, 0);

	if (cmd->tlvid == CHASSIS_ID_TLV) {
		if (errno || *end != '\0') {
			if (strcasecmp(argvalue,
				       "CHASSIS_ID_MAC_ADDRESS") == 0)
				subtype = CHASSIS_ID_MAC_ADDRESS;
			else if (strcasecmp(argvalue,
					    "CHASSIS_ID_NETWORK_ADDRESS") == 0)
				subtype = CHASSIS_ID_NETWORK_ADDRESS;
			else if (strcasecmp(argvalue,
					    "CHASSIS_ID_INTERFACE_NAME") == 0)
				subtype = CHASSIS_ID_INTERFACE_NAME;
			else {
				snprintf(obuf, obuf_len,
					 "subtype=[Unsupported subtype]");
				return cmd_invalid;
			}
		} else {
			switch (subtype) {
			case CHASSIS_ID_MAC_ADDRESS:
			case CHASSIS_ID_NETWORK_ADDRESS:
			case CHASSIS_ID_INTERFACE_NAME:
				break;
			default:
				snprintf(obuf, obuf_len,
					 "subtype=[Unsupported subtype]");
				return cmd_invalid;
			}
		}
	} else {
		if (errno || *end != '\0') {
			if (strcasecmp(argvalue,
				       "PORT_ID_MAC_ADDRESS") == 0)
				subtype = PORT_ID_MAC_ADDRESS;
			else if (strcasecmp(argvalue,
					    "PORT_ID_NETWORK_ADDRESS") == 0)
				subtype = PORT_ID_NETWORK_ADDRESS;
			else if (strcasecmp(argvalue,
					    "PORT_ID_INTERFACE_NAME") == 0)
				subtype = PORT_ID_INTERFACE_NAME;
			else {
				snprintf(obuf, obuf_len,
					 "subtype=[Unsupported subtype]");
				return cmd_invalid;
			}
		} else {
			switch (subtype) {
			case PORT_ID_MAC_ADDRESS:
			case PORT_ID_NETWORK_ADDRESS:
			case PORT_ID_INTERFACE_NAME:
				break;
			default:
				snprintf(obuf, obuf_len,
					 "subtype=[Unsupported subtype]");
				return cmd_invalid;
			}
		}
	}

	if (test)
		return cmd_success;

	if (md) {
		md->read_shm = 1;
		md->rebuild_chassis = 1;
		md->rebuild_portid = 1;
	}

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);
	snprintf(obuf, obuf_len, "%s=%s\n", arg, argvalue);
	set_config_setting(cmd->ifname, cmd->type,
			   arg_path, &subtype, CONFIG_TYPE_INT);

	somethingChangedLocal(cmd->ifname, cmd->type);

	return 0;
}

static int set_mand_subtype(struct cmd *cmd, char *arg, char *argvalue,
			    char *obuf, int obuf_len)
{
	return _set_mand_subtype(cmd, arg, argvalue, obuf, obuf_len, false);
}

static int test_mand_subtype(struct cmd *cmd, char *arg, char *argvalue,
			     char *obuf, int obuf_len)
{
	return _set_mand_subtype(cmd, arg, argvalue, obuf, obuf_len, true);
}

struct arg_handlers *mand_get_arg_handlers()
{
	return &arg_handlers[0];
}


int get_arg_adminstatus(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			char *obuf, int obuf_len)
{
	int value;
	char *s;

	if (cmd->cmd != cmd_get_lldp)
		return cmd_bad_params;

	if (cmd->tlvid != INVALID_TLVID)
		return cmd_bad_params;

	if (get_config_setting(cmd->ifname, cmd->type, arg, &value,
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
	
	snprintf(obuf, obuf_len, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		(unsigned int)strlen(s), s);
	return cmd_success;
}

int get_arg_tlvtxenable(struct cmd *cmd, char *arg, UNUSED char *argvalue,
			char *obuf, int obuf_len)
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
	
	snprintf(obuf, obuf_len, "%02x%s%04x%s", (unsigned int)strlen(arg), arg,
		(unsigned int)strlen(s), s);

	return cmd_success;
}

int handle_get_args(struct cmd *cmd, UNUSED char *arg, char *argvalue,
		   char *obuf, int obuf_len)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval;
	char *nbuf;
	int nbuf_len;

	nbuf = obuf;
	nbuf_len = obuf_len;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
			if (ah->handle_get && (ah->arg_class == TLV_ARG)) {
				rval = ah->handle_get(cmd, ah->arg, argvalue,
						      nbuf, nbuf_len);

				if (rval != cmd_success &&
				    rval != cmd_not_applicable)
					return rval;
				
				nbuf_len -= strlen(nbuf);
				nbuf = nbuf + strlen(nbuf);
			}
			ah++;
		}
	}
	return cmd_success;
}

int handle_get_arg(struct cmd *cmd, char *arg, char *argvalue,
		   char *obuf, int obuf_len)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
			if (!strcasecmp(ah->arg, arg) && ah->handle_get) {
				rval = ah->handle_get(cmd, ah->arg, argvalue,
						      obuf, obuf_len);

				if (rval != cmd_success &&
				    rval != cmd_not_applicable)
					return rval;
				else if (rval == cmd_success)
					status = rval;
				break;
			}
			ah++;
		}
	}
	return status;
}

int _set_arg_adminstatus(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, UNUSED int obuf_len, bool test)
{
	int value;

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

	if (test)
		return cmd_success;

	if (set_config_setting(cmd->ifname, cmd->type, arg, &value,
			       CONFIG_TYPE_INT))
		return cmd_failed;

	set_lldp_agent_admin(cmd->ifname, cmd->type, value);

	snprintf(obuf, obuf_len, "adminStatus = %s\n", argvalue);

	return cmd_success;
}

int test_arg_adminstatus(struct cmd *cmd, char *arg, char *argvalue,
			 char *obuf, int obuf_len)
{
	return _set_arg_adminstatus(cmd, arg, argvalue, obuf, obuf_len, true);
}

int set_arg_adminstatus(struct cmd *cmd, char *arg, char *argvalue,
			char *obuf, int obuf_len)
{
	return _set_arg_adminstatus(cmd, arg, argvalue, obuf, obuf_len, false);
}

int
set_arg_tlvtxenable(struct cmd *cmd, UNUSED char *arg, UNUSED char *argvalue,
		    UNUSED char *obuf, UNUSED int obuf_len)
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

int handle_test_arg(struct cmd *cmd, char *arg, char *argvalue,
		    char *obuf, int obuf_len)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
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
			ah++;
		}
	}

	return status;
}

int handle_set_arg(struct cmd *cmd, char *arg, char *argvalue,
		   char *obuf, int obuf_len)
{
	struct lldp_module *np;
	struct arg_handlers *ah;
	int rval, status = cmd_not_applicable;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (!np->ops->get_arg_handler)
			continue;
		if (!(ah = np->ops->get_arg_handler()))
			continue;
		while (ah->arg) {
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
			ah++;
		}
	}

	return status;
}


int get_tlvs(struct cmd *cmd, char *rbuf, int rlen)
{
	u8 tlvs[2048];
	int size = 0;
	int i;
	u32 tlvid;
	int off = 0;
	int moff = 0;
	u16 type, len;
	int res;

	/* VDP 0.2 protocol for nearest customer bridge only */
	if (cmd->tlvid == (OUI_IEEE_8021Qbg << 8)
	    && cmd->type != NEAREST_CUSTOMER_BRIDGE)
		return cmd_agent_not_supported;
	if (cmd->ops & op_local) {
		res = get_local_tlvs(cmd->ifname, cmd->type, &tlvs[0], &size);
		if (res)
			return res;
	} else if (cmd->ops & op_neighbor) {
		res = get_neighbor_tlvs(cmd->ifname, cmd->type, &tlvs[0], &size);
		if (res)
			return res;
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
		snprintf(rbuf + 2*i, rlen - strlen(rbuf), "%02x", tlvs[i]);
	}

	return cmd_success;
}

int get_agent_stats(struct cmd *cmd, char *rbuf, int rlen)
{
	int offset=0;
	struct agentstats stats;

	if (get_lldp_agent_statistics(cmd->ifname, &stats, cmd->type))
		return cmd_device_not_found;

	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsFramesOutTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsFramesDiscardedTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsFramesInErrorsTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsFramesInTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsTLVsDiscardedTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsTLVsUnrecognizedTotal);
	offset+=8;
	snprintf(rbuf+offset, rlen - strlen(rbuf),
		"%08x", stats.statsAgeoutsTotal);

	return cmd_success;
}

int mand_clif_cmd(UNUSED void  *data,
		  UNUSED struct sockaddr_un *from,
		  UNUSED socklen_t fromlen,
		  char *ibuf, int ilen,
		  char *rbuf, int rlen)
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

	/* pull out the command elements of the command message */
	hexstr2bin(ibuf+MSG_VER, (u8 *)&version, sizeof(u8));
	version = version >> 4;
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

	if (version == CLIF_MSG_VERSION) {
		hexstr2bin(ibuf+ioff, &cmd.type, sizeof(cmd.type));
		ioff += 2*sizeof(cmd.type);
	} else {
		cmd.type = NEAREST_BRIDGE;
		LLDPAD_WARN("deprecated client interface message version %x\n",
			     version);
	}

	if (cmd.cmd == cmd_gettlv || cmd.cmd == cmd_settlv) {
		hexstr2bin(ibuf+ioff, (u8 *)&cmd.tlvid, sizeof(cmd.tlvid));
		cmd.tlvid = ntohl(cmd.tlvid);
		ioff += 2*sizeof(cmd.tlvid);
	} else {
		cmd.tlvid = INVALID_TLVID;
	}

	/* count args and argvalus */
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

	switch (cmd.cmd) {
	case cmd_getstats:
		if (numargs)
			break;
		rstatus = get_agent_stats(&cmd, rbuf + roff, rlen - roff);
		break;
	case cmd_gettlv:
		snprintf(rbuf + roff, rlen - roff, "%08x", cmd.tlvid);
		roff+=8;
		if (!numargs) {
			if (cmd.ops & op_config) {
				if (cmd.ops & op_neighbor)
					break;
				rstatus = handle_get_args(&cmd, NULL, NULL,
							 rbuf + strlen(rbuf),
							 rlen - strlen(rbuf));
			} else {
				rstatus = get_tlvs(&cmd, rbuf+roff, rlen-roff);
			}
		} else if ((cmd.ops & op_config) && !(cmd.ops & op_neighbor)) {
			for (i = 0; i < numargs; i++)
				rstatus = handle_get_arg(&cmd, args[i], NULL,
							 rbuf + strlen(rbuf),
							 rlen - strlen(rbuf));
		}
		break;
	case cmd_settlv:
		snprintf(rbuf + roff, rlen - roff, "%08x", cmd.tlvid);
		roff+=8;
		for (i = 0; i < numargs; i++) {
			rstatus = handle_test_arg(&cmd, args[i], argvals[i],
						  rbuf+strlen(rbuf),
						  rlen - strlen(rbuf));
			if (rstatus != cmd_not_applicable &&
			    rstatus != cmd_success) {
				test_failed = true;
				break;
			}
		}
		if (test_failed)
			break;
		for (i = 0; i < numargs; i++)
			rstatus = handle_set_arg(&cmd, args[i], argvals[i],
						 rbuf + strlen(rbuf),
						 rlen - strlen(rbuf));
		break;
	case cmd_get_lldp:
		for (i = 0; i < numargs; i++)
			rstatus = handle_get_arg(&cmd, args[i], NULL,
						 rbuf + strlen(rbuf),
						 rlen - strlen(rbuf));
		break;
	case cmd_set_lldp:
		for (i = 0; i < numargs; i++)
			rstatus = handle_set_arg(&cmd, args[i], argvals[i],
						 rbuf + strlen(rbuf),
						 rlen - strlen(rbuf));
		break;
	default:
		rstatus = cmd_invalid;
		break;
	}

	free(argvals);
	free(args);
	return rstatus;
}
