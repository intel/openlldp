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
#include <sys/stat.h>
#include <stdlib.h>
#include "lldp.h"
#include "lldpad.h"
#include "dcb_events.h"
#include "lldp_mand_clif.h"
#include "lldp_dcbx_cmds.h"
#include "lldp_dcbx_cfg.h"
#include "lldpad_status.h"
#include "dcb_protocol.h"
#include "lldp/ports.h"
#include "config.h"
#include "lldp_dcbx_nl.h"
#include "lldp/states.h"
#include "lldp_dcbx.h"
#include "lldp_rtnl.h"
#include "messages.h"
#include "lldp_util.h"

extern u8 gdcbx_subtype;

static char *hexlist = "0123456789abcdef";
static char *hexlistcaps = "0123456789ABCDEF";

static int get_dcb_state(char *port_id, char *rbuf);
static cmd_status set_dcb_state(char *port_id, char *ibuf, int ilen);
static int get_dcbx_config(u8 cmd, char *rbuf);
static cmd_status set_dcbx_config(char *ibuf, int ilen);
static cmd_status get_pg_data(pg_attribs *pg_data, int cmd, char *port_id,
		int dcbx_st, char *rbuf);
static int set_pg_config(pg_attribs *pg_data, char *port_id, char *ibuf,
		int ilen);
static int set_pfc_config(pfc_attribs *pfc_data, char *port_id, char *ibuf,
		int ilen);
static int get_pfc_data(pfc_attribs *pfc_data, int cmd, char *port_id,
		int dcbx_st, char *rbuf);
static int set_app_config(app_attribs *app_data, char *port_id, u32 subtype,
		char *ibuf, int ilen);
static int get_app_data(app_attribs *app_data, int cmd, char *port_id,
		u32 subtype, char *rbuf);
static int set_llink_config(llink_attribs *app_data, char *port_id, u32 subtype,
		char *ibuf, int ilen);
static int get_llink_data(llink_attribs *llink_data, int cmd, char *port_id,
		u32 subtype, char *rbuf);
static cmd_status get_bwg_desc(char *port_id, char *ibuf, int ilen, char *rbuf);
static cmd_status set_bwg_desc(char *port_id, char *ibuf, int ilen);
static void set_protocol_data(feature_protocol_attribs *protocol, char *ifname,
		char *ibuf, int plen, int agenttype);
static cmd_status get_cmd_protocol_data(feature_protocol_attribs *protocol,
	u8 cmd, char *rbuf);

static int get_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int set_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);
static int test_arg_tlvtxenable(struct cmd *, char *, char *, char *, int);

static struct arg_handlers arg_handlers[] = {
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
	case (OUI_CEE_DCBX << 8) | 1:
	case (OUI_CEE_DCBX << 8) | 2:
		snprintf(arg_path, sizeof(arg_path), "%s%08x.%s",
			 TLVID_PREFIX, cmd->tlvid, arg);

		if (get_config_setting(cmd->ifname, cmd->type, arg_path, &value,
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
	
	snprintf(obuf, obuf_len, "%02zx%s%04zx%s", strlen(arg), arg,
		 strlen(s), s);

	return cmd_success;
}

void dont_advertise_dcbx_all(char *ifname, bool ad)
{
	int i, is_pfc;
	pfc_attribs pfc_data;
	pg_attribs pg_data;
	app_attribs app_data;
	llink_attribs llink_data;
	u32 event_flag = 0;

	is_pfc = get_pfc(ifname, &pfc_data);

	if (get_pg(ifname, &pg_data) == cmd_success) {
		pg_data.protocol.Advertise = ad;
		put_pg(ifname, &pg_data, &pfc_data);
		event_flag |= DCB_LOCAL_CHANGE_PG;
	}

	if (is_pfc == cmd_success) {
		pfc_data.protocol.Advertise = ad;
		put_pfc(ifname, &pfc_data);
		event_flag |= DCB_LOCAL_CHANGE_PFC;
	}

	for (i = 0; i < DCB_MAX_APPTLV ; i++) {
		if (get_app(ifname, (u32)i, &app_data) == cmd_success) {
			app_data.protocol.Advertise = ad;
			put_app(ifname, (u32)i, &app_data);
			event_flag |= DCB_LOCAL_CHANGE_APPTLV(i);
		}
	}

	for (i = 0; i < DCB_MAX_LLKTLV ; i++) {
		if (get_llink(ifname, (u32)i, &llink_data) == cmd_success) {
			llink_data.protocol.Advertise = ad;
			put_llink(ifname, (u32)i, &llink_data);
			event_flag |= DCB_LOCAL_CHANGE_LLINK;
		}
	}
}

static int _set_arg_tlvtxenable(struct cmd *cmd, char *arg, char *argvalue,
			       char *obuf, int obuf_len, bool test)
{
	int value;
	int current_value;
	char arg_path[256];

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;

	switch (cmd->tlvid) {
	case (OUI_CEE_DCBX << 8) | 1:
	case (OUI_CEE_DCBX << 8) | 2:
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

	current_value = is_tlv_txenabled(cmd->ifname, cmd->type, cmd->tlvid);

	snprintf(obuf, obuf_len, "enabled = %s\n", value ? "yes" : "no");

	if (current_value == value)
		return cmd_success;

	snprintf(arg_path, sizeof(arg_path), "%s%08x.%s", TLVID_PREFIX,
		 cmd->tlvid, arg);

	if (set_cfg(cmd->ifname, cmd->type, arg_path, &value,
		    CONFIG_TYPE_BOOL))
		return cmd_failed;

	dont_advertise_dcbx_all(cmd->ifname, value);
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

struct arg_handlers *dcbx_get_arg_handlers()
{
	return &arg_handlers[0];
}

static int get_dcb_state(char *port_id, char *rbuf)
{
	int state = 0;
	cmd_status rval = cmd_success;
	
	if (get_hw_state(port_id, &state))
		rval = cmd_failed;
	else
		sprintf(rbuf, "%01x", state);

	return (rval);
}

static cmd_status set_dcb_state(char *port_id, char *ibuf, int ilen)
{
	bool state;
	int off;
	int plen;
	cmd_status rval = cmd_success;

	plen=strlen(port_id);
	off = DCB_PORT_OFF + plen;

	if (ilen == (off + CFG_DCB_DLEN)) {
		state = (*(ibuf+off+DCB_STATE)) ^ '0';
		set_hw_state(port_id, state);
		rval = save_dcb_enable_state(port_id, state);
	} else {
		printf("error - setcommand has invalid argument length\n");
		rval = cmd_bad_params;
	}

	return rval;
}

static int get_dcbx_config(u8 cmd, char *rbuf)
{
	cmd_status rval = cmd_success;
	int dcbx_version;
	
	if (cmd == CMD_GET_CONFIG) {
		if (!get_dcbx_version(&dcbx_version))
			rval = cmd_failed;
	} else {
		dcbx_version = gdcbx_subtype;
	}

	if (rval == cmd_success)
		sprintf(rbuf, "%01x", dcbx_version);

	return (rval);
}

static cmd_status set_dcbx_config(char *ibuf, int ilen)
{
	int version;
	int off;
	cmd_status rval = cmd_success;

	off = DCBX_CFG_OFF;

	if (ilen == DCBX_CFG_OFF + CFG_DCBX_DLEN) {
		version = (*(ibuf+off+DCBX_VERSION)) ^ '0';
		switch (version) {
		case dcbx_subtype1:
		case dcbx_subtype2:
		case dcbx_force_subtype1:
		case dcbx_force_subtype2:
			rval = save_dcbx_version(version);
			break;
		default:
			rval = cmd_bad_params;
			break;
		}
	} else {
		printf("error - setcommand has invalid argument length\n");
		rval = cmd_bad_params;
	}

	return rval;
}

static cmd_status get_bwg_desc(char *port_id, char *ibuf, int ilen, char *rbuf)
{
	u8 pgid;
	int plen;
	char *desc_str = NULL;
	cmd_status rval = cmd_success;

	plen = strlen(port_id);

	if (ilen !=  DCB_PORT_OFF + plen + PG_DESC_GET_DLEN) {
		rval = cmd_bad_params;
	} else {
		pgid = *(ibuf + DCB_PORT_OFF + plen + PG_DESC_PGID) & 0x0f;

		if (pgid < 1 || pgid > 8) {
			rval = cmd_bad_params;
		} else {
			rval = get_bwg_descrpt(port_id, pgid-1, &desc_str);
			if (rval == cmd_success && desc_str) {
				sprintf(rbuf, "%01x%02x%s", pgid,
					(unsigned int) strlen(desc_str),
					desc_str);
				if (desc_str)
					free(desc_str);
			}
		}
	}
	return rval;
}

static cmd_status set_bwg_desc(char *port_id, char *ibuf, int ilen)
{
	u8 pgid;
	u8 desc_len = 0;
	int plen;
	cmd_status rval = cmd_success;

	plen = strlen(port_id);
	if (ilen >=  DCB_PORT_OFF + plen + PG_DESC_SET_DLEN) {
		hexstr2bin(ibuf+DCB_PORT_OFF + plen + PG_DESC_LEN,
			&desc_len, sizeof(desc_len));
		pgid = *(ibuf + DCB_PORT_OFF + plen + PG_DESC_PGID) & 0x0f;
	} else {
		printf("ilen[%d] < %d\n", ilen, DCB_PORT_OFF + plen +
			PG_DESC_SET_DLEN);
		return cmd_bad_params;
	}

	if (ilen ==  DCB_PORT_OFF + plen + PG_DESC_SET_DLEN + desc_len) {
		if (pgid < 1 || pgid > 8 || desc_len > 100) {
			printf("pgid = %d, desc_len = %d\n", pgid, desc_len);
			rval = cmd_bad_params;
		} else {
			rval = put_bwg_descrpt(port_id, pgid-1,
				ibuf+DCB_PORT_OFF+plen+PG_DESC_DATA);
		}
	} else {
		printf("ilen[%d] != %d\n", ilen, DCB_PORT_OFF + plen +
			PG_DESC_SET_DLEN + desc_len);
		rval = cmd_bad_params;
	}

	return rval;
}

static void set_app_protocol_data(char *ifname, char *ibuf, int plen, int ilen,
				  int subtype, int agenttype)
{
	u8 aflag, eflag, wflag;
	int status, last, i;
	app_attribs app_data;
	feature_protocol_attribs *protocol;

	status = get_app(ifname, (u32)subtype, &app_data);
	if (status != cmd_success) {
		printf("%s %s: error[%d] getting APP data.\n",
			__func__, ifname, status);
		return;
	}

	protocol = &app_data.protocol;
	last = protocol->Advertise;

	aflag = *(ibuf+DCB_PORT_OFF+plen+CFG_ADVERTISE);
	if (aflag == '0' || aflag == '1')
		protocol->Advertise = aflag & 0x01;

	status = set_app_config(&app_data,
				ifname,
				(u32)subtype,
				ibuf,
				ilen);

	if (status != cmd_success)
		printf("%s %s: error[%d] set_app_config failed\n",
			__func__, ifname, status);

	if (last != protocol->Advertise && protocol->Advertise) {
		tlv_enabletx(ifname, agenttype, (OUI_CEE_DCBX << 8) |
			     protocol->dcbx_st);
	}

	eflag = *(ibuf+DCB_PORT_OFF+plen+CFG_ENABLE);
	wflag = *(ibuf+DCB_PORT_OFF+plen+CFG_WILLING);

	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		status = get_app(ifname, (u32)i, &app_data);
		if (status != cmd_success)
			continue;

		protocol = &app_data.protocol;

		if (eflag == '0' || eflag == '1')
			protocol->Enable = eflag & 0x01;

		if (wflag == '0' || wflag == '1')
			protocol->Willing = wflag & 0x01;

		status = put_app(ifname, i, &app_data);
		if (status != cmd_success)
			printf("%s %s: error[%d] set_app_config failed\n",
				__func__, ifname, status);
	}

	somethingChangedLocal(ifname, agenttype);
}

static void set_protocol_data(feature_protocol_attribs *protocol, char *ifname,
			      char *ibuf, int plen, int agenttype)
{
	u8 flag;
	int last;

	flag = *(ibuf+DCB_PORT_OFF+plen+CFG_ENABLE);
	if (flag == '0' || flag == '1')
		protocol->Enable = flag & 0x01;

	flag = *(ibuf+DCB_PORT_OFF+plen+CFG_ADVERTISE);
	if (flag == '0' || flag == '1') {
		last = protocol->Advertise;
		protocol->Advertise = flag & 0x01;
		if (last != protocol->Advertise && protocol->Advertise) {
			tlv_enabletx(ifname, agenttype, (OUI_CEE_DCBX << 8) |
				     protocol->dcbx_st);
			somethingChangedLocal(ifname, agenttype);
		}
	}

	flag = *(ibuf+DCB_PORT_OFF+plen+CFG_WILLING);
	if (flag == '0' || flag == '1')
		protocol->Willing = flag & 0x01;
}

/* rbuf points to correct destination location */
static cmd_status get_cmd_protocol_data(feature_protocol_attribs *protocol,
	u8 cmd, char *rbuf)
{
	cmd_status rval = cmd_success;

	switch(cmd) {
	case CMD_GET_CONFIG:
		sprintf(rbuf, "%1x%1x%1x",
			protocol->Enable,
			protocol->Advertise,
			protocol->Willing);
		break;
	case CMD_GET_OPER:
		sprintf(rbuf, "%02x%02x%02x%1x%1x",
			protocol->Oper_version,
			protocol->Max_version,
			protocol->Error_Flag,
			protocol->OperMode,
			protocol->Syncd);
		break;
	case CMD_GET_PEER:
		if (protocol->TLVPresent == true)
			sprintf(rbuf, "%1x%1x%02x%02x%1x%1x",
				protocol->Enable,
				protocol->Willing,
				protocol->Oper_version,
				protocol->Max_version,
				protocol->Error,
				protocol->dcbx_st);
		else
			rval = cmd_peer_not_present;
		break;
	}
	return rval;
}

static int handle_dcbx_cmd(u8 cmd, u8 feature, char *ibuf, int ilen, char *rbuf)
{
	int status = cmd_success;

	if (ilen < DCBX_CFG_OFF)
		return cmd_invalid;

	/* append standard dcb command response content */
	sprintf(rbuf , "%*.*s", DCBX_CFG_OFF, DCBX_CFG_OFF, ibuf);

	switch(feature) {
	case FEATURE_DCBX:
		if (cmd == CMD_SET_CONFIG) {
			status = set_dcbx_config(ibuf, ilen);
		} else if (cmd != CMD_GET_PEER) {
			status = get_dcbx_config(cmd, rbuf+strlen(rbuf));
		} else {
			status = cmd_invalid;
		}
		break;
	default:
		break;
	}

	return status;
}

int dcbx_clif_cmd(void *data,
		  UNUSED struct sockaddr_un *from,
		  UNUSED socklen_t fromlen,
		  char *ibuf, int ilen,
		  char *rbuf, int rlen)
{
	u8 status = cmd_success;
	u8 cmd;
	u8 feature;
	u8 subtype;
	u8 plen;
	char port_id[MAX_U8_BUF];
	pg_attribs pg_data;
	pfc_attribs pfc_data;
	app_attribs app_data;
	llink_attribs llink_data;
	struct port *port;
	struct dcbx_tlvs *dcbx;

	data = (struct clif_data *) data;

	if (hexstr2bin(ibuf+DCB_CMD_OFF, &cmd, sizeof(cmd)) ||
		hexstr2bin(ibuf+DCB_FEATURE_OFF, &feature, sizeof(feature)))
		return cmd_invalid;

	if (feature == FEATURE_DCBX)
		return handle_dcbx_cmd(cmd, feature, ibuf, ilen, rbuf);

	if (hexstr2bin(ibuf+DCB_SUBTYPE_OFF, &subtype, sizeof(subtype)) ||
		hexstr2bin(ibuf+DCB_PORTLEN_OFF, &plen, sizeof(plen)))
		return cmd_invalid;

	if (ilen < DCB_PORT_OFF)
		return cmd_invalid;
	
	if (ibuf[DCB_VER_OFF] < (CLIF_DCBMSG_VERSION | 0x30)) {
		printf("unsupported client interface message version %x %x\n",
			ibuf[DCB_VER_OFF], CLIF_DCBMSG_VERSION | 0x30);
		return cmd_ctrl_vers_not_compatible;
	}

	if (ilen < DCB_PORT_OFF+plen) {
		printf("command too short\n");
		return cmd_invalid;
	}

	/* append standard dcb command response content */
	snprintf(rbuf , rlen, "%*.*s",
		 DCB_PORT_OFF+plen, DCB_PORT_OFF+plen, ibuf);

	memcpy(port_id, ibuf+DCB_PORT_OFF, plen);
	port_id[plen] = '\0';

	/* Confirm port is a lldpad managed port */
	port = port_find_by_name(port_id);
	if (!port)
		return cmd_device_not_found;

	dcbx = dcbx_data(port->ifname);
	if (!dcbx)
		return cmd_device_not_found;

	/* OPER and PEER cmd not applicable while in IEEE-DCBX modes */
	if (dcbx->active == 0 && (cmd == CMD_GET_PEER || cmd == CMD_GET_OPER))
		return cmd_not_applicable;

	switch(feature) {
	case FEATURE_DCB:
		if (cmd == CMD_SET_CONFIG)
			status = set_dcb_state(port_id, ibuf, ilen);
		else if (cmd == CMD_GET_CONFIG)
			status = get_dcb_state(port_id, rbuf+strlen(rbuf));
		else
			status = cmd_invalid;
		break;

	case FEATURE_PG:
		if (cmd == CMD_GET_PEER) {
			status = get_peer_pg(port_id, &pg_data);
		} else {
			status = get_pg(port_id, &pg_data);
		}

		if (status != cmd_success) {
			printf("error[%d] getting PG data for %s\n",
				status, port_id);
			return status;
		}

		if (cmd == CMD_SET_CONFIG) {
			if (ilen < (DCB_PORT_OFF + plen + CFG_LEN)) {
				printf("set command too short\n");
				status = cmd_invalid;
			} else {
				set_protocol_data(&pg_data.protocol, port_id,
						  ibuf, plen, NEAREST_BRIDGE);
				status = set_pg_config(&pg_data, port_id, ibuf,
					ilen);
			}
		} else {
			status = get_cmd_protocol_data(&pg_data.protocol, cmd,
					rbuf+strlen(rbuf));
			if (status == cmd_success)
				status = get_pg_data(&pg_data, cmd, port_id,
					pg_data.protocol.dcbx_st,
					rbuf+strlen(rbuf));
		}
		break;

	case FEATURE_PFC:
		if (cmd == CMD_GET_PEER) {
			status = get_peer_pfc(port_id, &pfc_data);
		} else {
			status = get_pfc(port_id, &pfc_data);
		}

		if (status != cmd_success) {
			printf("error[%d] getting PFC data for %s\n",
					status, port_id);
			return status;
		}

		if (cmd == CMD_SET_CONFIG) {
			if (ilen < (DCB_PORT_OFF + plen + CFG_LEN)) {
				printf("set command too short\n");
				status = cmd_failed;
			} else {
				set_protocol_data(&pfc_data.protocol, port_id,
						  ibuf, plen, NEAREST_BRIDGE);
				status = set_pfc_config(&pfc_data, port_id,
					ibuf, ilen);
			}
		} else {
			status = get_cmd_protocol_data(&pfc_data.protocol,
				cmd, rbuf+strlen(rbuf));
			if (status == cmd_success)
				status = get_pfc_data(&pfc_data, cmd,
					port_id, pfc_data.protocol.dcbx_st,
					rbuf+strlen(rbuf));
		}
		break;


	case FEATURE_APP:
		if (cmd == CMD_GET_PEER) {
			status = get_peer_app(port_id, (u32)subtype, &app_data);
		} else {
			status = get_app(port_id, (u32)subtype, &app_data);
		}

		if (status != cmd_success) {
			printf("error[%d] getting APP data for %s\n", status,
				port_id);
			return status;
		}

		if (cmd == CMD_SET_CONFIG) {
			if (ilen < (DCB_PORT_OFF + plen + CFG_LEN)) {
				printf("set command too short\n");
				status = cmd_failed;
			} else {
				set_app_protocol_data(port_id, ibuf, plen, ilen,
						      subtype, NEAREST_BRIDGE);
			}
		} else {
			status = get_cmd_protocol_data(&app_data.protocol, cmd,
				rbuf+strlen(rbuf));
			if (status == cmd_success)
				status = get_app_data(&app_data, cmd, port_id,
					subtype, rbuf + strlen(rbuf));
		}
		break;

	case FEATURE_LLINK:
		if (cmd == CMD_GET_PEER) {
			status = get_peer_llink(port_id, (u32)subtype,
				&llink_data);
		} else {
			status = get_llink(port_id, (u32)subtype, &llink_data);
		}

		if (status != cmd_success) {
			printf("error[%d] getting APP data for %s\n", status,
				port_id);
			return status;
		}

		if (cmd == CMD_SET_CONFIG) {
			if (ilen < (DCB_PORT_OFF + plen + CFG_LEN)) {
				printf("set command too short\n");
				status = cmd_failed;
			} else {
				set_protocol_data(&llink_data.protocol, port_id,
						  ibuf, plen, NEAREST_BRIDGE);
				status = set_llink_config(&llink_data, port_id,
					(u32)subtype, ibuf, ilen);
			}
		} else {
			status = get_cmd_protocol_data(&llink_data.protocol,
				cmd, rbuf+strlen(rbuf));
			if (status == cmd_success)
				status = get_llink_data(&llink_data, cmd,
					port_id, subtype, rbuf + strlen(rbuf));
		}
		break;

	case FEATURE_PG_DESC:
		if (cmd == CMD_GET_CONFIG) {
			status = get_bwg_desc(port_id, ibuf, ilen,
					      rbuf+strlen(rbuf));

			if (status != cmd_success) {
				printf("error[%d] getting BWG desc for %s\n",
					status, port_id);
				return status;
			}
		} else if (cmd == CMD_SET_CONFIG) {
			status = set_bwg_desc(port_id, ibuf, ilen);
		}

		break;
	default:
		break;
	}

	return status;
}


/* rbuf points to correct destination location */
static cmd_status get_pg_data(pg_attribs *pg_data, int cmd, char *port_id,
	int dcbx_st, char *rbuf)
{
	int i;
	int status;
	int value;

	switch (cmd) {
	case CMD_GET_CONFIG: /* already have the data object */
	case CMD_GET_PEER:
		break;
	case CMD_GET_OPER:
		status = get_oper_pg(port_id, pg_data);
		if (status != cmd_success) {
			printf("error[%d] getting oper PG data for %s\n",
				status, port_id);
			return status;
		}
		break;
	}

	for (i = 0; i < MAX_USER_PRIORITIES; i++)
		sprintf(rbuf+PG_UP2TC(i), "%1x", pg_data->tx.up[i].pgid);
	for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++)
		sprintf(rbuf+PG_PG_PCNT(i), "%02x", pg_data->tx.pg_percent[i]);
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if (pg_data->tx.up[i].strict_priority == dcb_link)
			value = LINK_STRICT_PGID;
		else
			value = pg_data->tx.up[i].pgid;
		sprintf(rbuf+PG_UP_PGID(i), "%1X", value);
	}
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if ((cmd != CMD_GET_PEER) ||
			(cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype1))
			sprintf(rbuf+PG_UP_PCNT(i), "%02x",
				pg_data->tx.up[i].percent_of_pg_cap);
		else if (cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype2)
			sprintf(rbuf+PG_UP_PCNT(i), "%c%c",
				CLIF_NOT_SUPPLIED, CLIF_NOT_SUPPLIED);
	}
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		if ((cmd != CMD_GET_PEER) ||
			(cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype1)) {
			if (pg_data->tx.up[i].strict_priority == dcb_link)
				value = dcb_none;
			else
				value = pg_data->tx.up[i].strict_priority;
			sprintf(rbuf+PG_UP_STRICT(i), "%1x", value);
		} else if (cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype2) {
			sprintf(rbuf+PG_UP_STRICT(i), "%c", CLIF_NOT_SUPPLIED);
		}
	}

	if ((cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype1) ||
		(cmd == CMD_GET_OPER))
		sprintf(rbuf+PG_UP_NUM_TC, "%c", CLIF_NOT_SUPPLIED);
	else
		sprintf(rbuf+PG_UP_NUM_TC, "%1x", pg_data->num_tcs);

	return cmd_success;
}

/* rbuf points to correct destination location */
static int get_pfc_data(pfc_attribs *pfc_data, int cmd, char *port_id,
	int dcbx_st, char *rbuf)
{
	int i;
	int status;

	switch (cmd) {
	case CMD_GET_CONFIG: /* already have the data object */
		break;
	case CMD_GET_OPER:
		status = get_oper_pfc(port_id, pfc_data);
		if (status != cmd_success) {
			printf("error[%d] getting oper PFC data for %s\n",
				status, port_id);
			return status;
		}
		break;
	case CMD_GET_PEER:
		status = get_peer_pfc(port_id, pfc_data);
		if (status != cmd_success) {
			printf("error[%d] getting peer PFC data for %s\n",
				status, port_id);
			return status;
		}
		break;
	}
	
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		sprintf(rbuf+PFC_UP(i), "%1x", pfc_data->admin[i]);
	}

	if ((cmd == CMD_GET_PEER && dcbx_st == dcbx_subtype1) ||
		(cmd == CMD_GET_OPER))
		sprintf(rbuf+PFC_NUM_TC, "%c", CLIF_NOT_SUPPLIED);
	else
		sprintf(rbuf+PFC_NUM_TC, "%1x", pfc_data->num_tcs);

	return cmd_success;
}

/* rbuf points to correct destination location */
static int get_app_data(app_attribs *app_data, int cmd, char *port_id,
		u32 subtype, char *rbuf)
{
	int status;
	unsigned int i;

	switch (cmd) {
	case CMD_GET_CONFIG: /* already have the data object */
		break;
	case CMD_GET_OPER:
		status = get_oper_app(port_id, subtype, app_data);
		if (status != cmd_success) {
			printf("error[%d] getting oper App data for %s\n",
				status, port_id);
			return status;
		}
		break;
	case CMD_GET_PEER:
		status = get_peer_app(port_id, subtype, app_data);
		if (status != cmd_success) {
			printf("error[%d] getting peer app data for %s\n",
				status, port_id);
			return status;
		}
		break;
	}
	
	sprintf(rbuf+APP_LEN, "%02x", 2*app_data->Length);
	
	for (i=0; i<app_data->Length; i++)
		sprintf(rbuf+APP_DATA+2*i, "%02x", *(app_data->AppData+i));

	return cmd_success;
}

/* rbuf points to correct destination location */
static int get_llink_data(llink_attribs *llink_data, int cmd, char *port_id,
		u32 subtype, char *rbuf)
{
	int status;

	switch (cmd) {
	case CMD_GET_CONFIG: /* already have the data object */
		break;
	case CMD_GET_OPER:
		status = get_oper_llink(port_id, subtype, llink_data);
		if (status != cmd_success) {
			printf("error[%d] getting oper logical link data "
				"for %s\n", status, port_id);
			return status;
		}
		break;
	case CMD_GET_PEER:
		status = get_peer_llink(port_id, subtype, llink_data);
		if (status != cmd_success) {
			printf("error[%d] getting peer logical link data "
				"for %s\n", status, port_id);
			return status;
		}
		break;
	}
	
	sprintf(rbuf+LLINK_STATUS, "%1x", llink_data->llink.llink_status);

	return cmd_success;
}


static int set_pg_config(pg_attribs *pg_data, char *port_id, char *ibuf,
	int ilen)
{
	pfc_attribs pfc_data;
	full_dcb_attrib_ptrs dcb_data;
	u8 flag;
	cmd_status status = cmd_success;
	int i, is_pfc;
	int plen;
	int off;
	bool used[MAX_BANDWIDTH_GROUPS];
	bool uppcts_changed = false;

	plen=strlen(port_id);
	off = DCB_PORT_OFF + plen + CFG_LEN;

	if (ilen == (off + CFG_PG_DLEN)) {
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			flag = *(ibuf+off+PG_UP2TC(i));
			if (flag == CLIF_NOT_SUPPLIED)
				continue;

			if ((flag & 0x07) >= pg_data->num_tcs)
				return cmd_bad_params;

			pg_data->tx.up[i].pgid = flag & 0x07;
			pg_data->rx.up[i].pgid = flag & 0x07;
		}
		memset(used, false, sizeof(used));
		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			if (*(ibuf+off+PG_PG_PCNT(i)) == CLIF_NOT_SUPPLIED)
				continue;
			if (hexstr2bin(ibuf+off+PG_PG_PCNT(i),
				&flag, sizeof(flag)))
				return cmd_bad_params;
			pg_data->tx.pg_percent[i] = flag;
			pg_data->rx.pg_percent[i] = flag;
		}
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			flag = *(ibuf+off+PG_UP_PGID(i));
			if (flag == CLIF_NOT_SUPPLIED) {
				if (pg_data->tx.up[i].strict_priority ==
					dcb_link)
					flag = LINK_STRICT_PGID;
				else
					flag = pg_data->tx.up[i].pgid;
			} else {
				if (flag == hexlist[LINK_STRICT_PGID] ||
					flag == hexlistcaps[LINK_STRICT_PGID])
					flag = LINK_STRICT_PGID;
				else
					flag = flag & 0x0f;
				pg_data->tx.up[i].pgid = flag;
				pg_data->rx.up[i].pgid = flag;
			}

			/* keep track of which PGID's in the range of
			 * 0-7 are being used (not counting pre-existing
			 * link strict PGID).
			*/
			if (flag < MAX_BANDWIDTH_GROUPS)
				used[flag] = true;
		}
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			if (*(ibuf+off+PG_UP_PCNT(i)) == CLIF_NOT_SUPPLIED)
				continue;
			uppcts_changed = true;
			if (hexstr2bin(ibuf+off+PG_UP_PCNT(i),
				&flag, sizeof(flag)))
				return cmd_bad_params;
			pg_data->tx.up[i].percent_of_pg_cap = flag;
			pg_data->rx.up[i].percent_of_pg_cap = flag;
		}
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			flag = *(ibuf+off+PG_UP_STRICT(i));
			if (flag == CLIF_NOT_SUPPLIED)
				continue;
			/* only set or clear the group strict bit.
			 * the link strict bit will be handled later.
			*/
			flag = flag & 0x01;
			if (flag) {
				pg_data->tx.up[i].strict_priority |= flag;
				pg_data->rx.up[i].strict_priority |= flag;
			} else {
				pg_data->tx.up[i].strict_priority &= ~dcb_group;
				pg_data->rx.up[i].strict_priority &= ~dcb_group;
			}
		}

		/* find the first unused PGID in range 0-7 */
		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++)
			if (!used[i])
				break;

		/* The end goal here is to have all of the user priorities
		 * assigned to the link strict PGID to use the lowest
		 * unused value in the range 0-7.  The strict_priority field
		 * is set to 'dcb_link' as well for the link strict PGID.
		 */
		flag = i;
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			if (pg_data->tx.up[i].pgid == LINK_STRICT_PGID ||
				(!used[pg_data->tx.up[i].pgid] &&
				pg_data->tx.up[i].strict_priority & dcb_link)) {
				pg_data->tx.up[i].pgid = flag;
				pg_data->rx.up[i].pgid = flag;
				pg_data->tx.up[i].strict_priority = dcb_link;
				pg_data->rx.up[i].strict_priority = dcb_link;
			} else {
				pg_data->tx.up[i].strict_priority &= ~dcb_link;
				pg_data->rx.up[i].strict_priority &= ~dcb_link;
			}
		}
	} else if (ilen != off) {
		printf("error - setcommand has invalid argument length\n");
		return cmd_bad_params;
	}

	memset((void *)&dcb_data, 0, sizeof(dcb_data));
	dcb_data.pg = pg_data;
	status = dcb_check_config(&dcb_data);

	/* if the rule checking fails and client did not supply
	 * user priority percentages, then compute new percentages
	 * and try one more time.
	*/
	if (status == cmd_bad_params && !uppcts_changed) {
		rebalance_uppcts(pg_data);
		status = dcb_check_config(&dcb_data);
	}

	if (status != cmd_success) {
		printf("invalid DCB settings\n");
		return status;
	}

	is_pfc = get_pfc(port_id, &pfc_data);
	if (is_pfc == cmd_success)
		status = put_pg(port_id, pg_data, &pfc_data);
	else
		status = put_pg(port_id, pg_data, NULL);

	if (status != cmd_success)
		printf("error[%d] setting PG data for %s\n", status, port_id);
	

	return status;
}

static int set_pfc_config(pfc_attribs *pfc_data, char *port_id, char *ibuf,
	int ilen)
{
	u8 flag;
	cmd_status status = cmd_success;
	int i;
	int off;
	int plen;
	
	plen=strlen(port_id);
	off = DCB_PORT_OFF + plen + CFG_LEN;

	if (ilen == (off + CFG_PFC_DLEN)) {
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			flag = (*(ibuf+off+PFC_UP(i))) & 0x07;
			if (flag == CLIF_NOT_SUPPLIED)
				continue;
			if (flag)
				pfc_data->admin[i] = pfc_enabled;
			else
				pfc_data->admin[i] = pfc_disabled;
		}
	} else if (ilen != off) {
		/* at least needs to include the protocol settings */
		printf("error - setcommand has invalid argument length\n");
		return cmd_failed;
	}

	status = put_pfc(port_id, pfc_data);
	if (status != cmd_success)
		printf("error[%d] setting PFC data for %s\n", status, port_id);

	return status;
}

static int set_app_config(app_attribs *app_data, char *port_id, u32 subtype,
		char *ibuf, int ilen)
{
	cmd_status status = cmd_success;
	int off;
	int plen;
	u8 applen = 0;
	
	plen=strlen(port_id);
	off = DCB_PORT_OFF + plen + CFG_LEN;

	hexstr2bin(ibuf+off+APP_LEN, &applen, sizeof(applen));

	if (ilen == (off + APP_DATA + applen)) {
		app_data->Length = applen/2;
		if (hexstr2bin(ibuf+off+APP_DATA, app_data->AppData, applen/2))
			return cmd_bad_params;
	} else if (ilen != off) {
		/* at least needs to include the protocol settings */
		printf("error - setcommand has invalid argument length\n");
		return cmd_failed;
	}

	status = put_app(port_id, subtype, app_data);

	if (status != cmd_success)
		printf("error[%d] setting APP data for %s\n", status, port_id);

	return status;
}

static int set_llink_config(llink_attribs *llink_data, char *port_id,
		u32 subtype, char *ibuf, int ilen)
{
	cmd_status status = cmd_success;
	int off;
	int value;
	
	off = DCB_PORT_OFF + strlen(port_id) + CFG_LEN;

	if (ilen != off + LLINK_DLEN) {
		/* at least needs to include the protocol settings */
		printf("error - setcommand has invalid argument length\n");
		return cmd_failed;
	}

	value = *(ibuf+off+LLINK_STATUS);
	if (value != CLIF_NOT_SUPPLIED)
		llink_data->llink.llink_status = value & 0x0f;

	status = put_llink(port_id, subtype, llink_data);

	if (status != cmd_success)
		printf("error[%d] setting logical link data for %s\n",
			status, port_id);

	return status;
}


void pfc_event(char *dn, u32 events)
{
	char ebuf[512];

	if (snprintf(ebuf, sizeof(ebuf), "%01x%02x%s%02x00%1x%1x",
		CLIF_EV_VERSION, (unsigned int)strlen(dn), dn, FEATURE_PFC,
		!!(events & EVENT_OPERMODE),
		!!(events & EVENT_OPERATTR)) < (int)sizeof(ebuf))
		send_event(MSG_EVENT, 0, ebuf);
}

void pg_event(char *dn, u32 events)
{
	char ebuf[512];

	if (snprintf(ebuf, sizeof(ebuf), "%01x%02x%s%02x00%1x%1x",
		CLIF_EV_VERSION, (unsigned int)strlen(dn), dn, FEATURE_PG,
		!!(events & EVENT_OPERMODE),
		!!(events & EVENT_OPERATTR)) < (int)sizeof(ebuf))
		send_event(MSG_EVENT, 0, ebuf);
}

void app_event(char *dn, u32 subtype, u32 events)
{
	char ebuf[512];

	if (snprintf(ebuf, sizeof(ebuf), "%01x%02x%s%02x%02x%1x%1x",
		CLIF_EV_VERSION, (unsigned int)strlen(dn), dn, FEATURE_APP,
		subtype,
		!!(events & EVENT_OPERMODE),
		!!(events & EVENT_OPERATTR)) < (int)sizeof(ebuf))
		send_event(MSG_EVENT, 0, ebuf);
}

void llink_event(char *dn, u32 subtype, u32 events)
{
	char ebuf[512];

	if (snprintf(ebuf, sizeof(ebuf), "%01x%02x%s%02x%02x%1x%1x",
		CLIF_EV_VERSION, (unsigned int)strlen(dn), dn, FEATURE_LLINK,
		subtype,
		!!(events & EVENT_OPERMODE),
		!!(events & EVENT_OPERATTR)) < (int)sizeof(ebuf))
		send_event(MSG_EVENT, 0, ebuf);
}

