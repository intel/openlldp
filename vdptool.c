/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) IBM Corp. 2014

  Substantially modified from:
  hostapd-0.5.7
  Copyright (c) 2002-2007, Jouni Malinen <jkmaline@cc.hut.fi> and
  contributors

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

/*
 * Thomas Richter, IBM LTC Boeblingen, Germany, Feb 2014
 *
 * Command line interface tool to connect to vdp module of lldpad to
 * set and query VSI profile settings.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <sys/queue.h>

#include "version.h"
#include "clif.h"
#include "clif_msgs.h"
#include "lldp_mod.h"

#include "qbg22.h"
#include "qbg_vdp22_clif.h"
#include "lldp_util.h"
#include "qbg_vdp22def.h"
#include "qbg_vdp22_oui.h"

#define OUI_ENCODE_HNDLR(name) name##_oui_encode_hndlr
#define OUI_PRNT_DECODE_HNDLR(name) name##_oui_print_decode_hndlr

#define EXTERN_OUI_FN(name) \
	extern bool name##_oui_encode_hndlr(char *, char *, size_t); \
	extern void name##_oui_print_decode_hndlr(char *)

/* The handler declaration  for encoding OUI specific information should be
 * here. The corresponding decoder handler should be in lldpad.
 */

EXTERN_OUI_FN(cisco);

/* The OUI specific handlers should be added here */

vdptool_oui_hndlr_tbl_t oui_hndlr_tbl[] = {
	{"cisco", OUI_ENCODE_HNDLR(cisco), OUI_PRNT_DECODE_HNDLR(cisco)}
};


static char *print_vdp_status(enum vdp22_cmd_status status)
{
	char *str;

	switch (status) {
	case cmd_vdp_prot_no_support:
		str = "VDP protocol not supported on interface";
		break;
	case cmd_vdp_nomem:
		str = "Not enough memory";
		break;
	case cmd_vdp_busy:
		str = "VSI association in progress";
		break;
	default:
		str = "Unknown status";
		break;
	}
	return str;
}

static char *print_status(cmd_status status)
{
	char *str;

	switch (status) {
	case cmd_success:
		str = "Successful";
		break;
	case cmd_failed:
		str = "Failed";
		break;
	case cmd_device_not_found:
		str = "Device not found or inactive";
		break;
	case cmd_agent_not_found:
		str = "Agent instance for device not found";
		break;
	case cmd_invalid:
		str = "Invalid command";
		break;
	case cmd_bad_params:
		str = "Invalid parameters";
		break;
	case cmd_peer_not_present:
		str = "Peer feature not present";
		break;
	case cmd_ctrl_vers_not_compatible:
		str = "Version not compatible";
		break;
	case cmd_not_capable:
		str = "Device not capable";
		break;
	case cmd_not_applicable:
		str = "Command not applicable";
		break;
	case cmd_no_access:
		str = "Access denied";
		break;
	case cmd_agent_not_supported:
		str = "TLV does not support agent type";
		break;
	default:
		str = print_vdp_status((enum vdp22_cmd_status)status);
		break;
	}
	return str;
}

static void get_arg_value(char *str, char **arg, char **argval)
{
	unsigned int i;

	for (i = 0; i < strlen(str); i++)
		if (!isprint(str[i]))
			return;

	for (i = 0; i < strlen(str); i++)
		if (str[i] == '=')
			break;

	if (i < strlen(str)) {
		str[i] = '\0';
		*argval = &str[i+1];
	}
	*arg = str;
}

static char *get_oui_name(char *argvals)
{
	char *oui_loc;

	oui_loc = strchr(argvals, ',');
	if (oui_loc == NULL)
		return NULL;
	*oui_loc = '\0';
	return oui_loc + 1;
}

static void fill_oui_hdr(vdptool_oui_data_t *oui_data, char *oui_name)
{
	STRNCPY_TERMINATED(oui_data->oui_name, oui_name, sizeof(oui_data->oui_name));
	snprintf(oui_data->data, sizeof(oui_data->data), "%02x%s",
		 (unsigned int)strlen(oui_data->oui_name), oui_data->oui_name);
}

static bool run_vdptool_oui_hndlr(vdptool_oui_data_t *oui_data, char *argvals)
{
	int cnt = 0, tbl_size;
	char *dst;
	size_t len = 0;

	tbl_size = sizeof(oui_hndlr_tbl) / sizeof(vdptool_oui_hndlr_tbl_t);
	for (cnt = 0; cnt < tbl_size; cnt++) {
		if (!strncmp(oui_hndlr_tbl[cnt].oui_name, oui_data->oui_name,
			     VDP22_OUI_MAX_NAME)) {
			len = strlen(oui_data->data);
			if (len >= sizeof(oui_data->data))
				return false;
			dst = oui_data->data + len;
			return oui_hndlr_tbl[cnt].oui_cli_encode_hndlr(dst,
								argvals, len);
		}
	}
	return false;
}

/*
 * The OUI can be input in many ways.
 * It could be vdptool .... -c oui=companyA,Data1 -c oui=companyB,Data2 \
 *			    -c oui=companyA,Data3
 * Or
 * vdptool .... -c oui=companyA,Data1Data3 -c oui=companyB,data2
 * This function takes care of both the case cases
 *
 * Anything after the comma in OUI data field is Org specific and it's upto
 * the respective organization specific handlers to encode it so that it could
 * be decoded appropriately by the ORG specific handlers inside lldpad.
 * That is, Data1 and Data3 is ORG companyA specific and the OUI handlers
 * of ORG companyA in vdptool and lldpad is responsible for encoding/decoding.
 *
 * Irrespective of how the command line interface to vdptool is, the input to
 * lldpad is always the same. i.e. KeywordlenKeywordDatalenData
 * For OUI, the data field will have the complete OUI data starting with
 * ORG name (e.g companyA). So, in order to call the right handler routine,
 * the OUI data field is split as OUInamelenOUInameOUIData.
 * OUInamelen is 2B.
 */

static bool rewrite_oui_argval(char *argvals, vdptool_oui_data_t **oui_data,
			       int total_oui)
{
	char *new_oui_argvals, *new_oui_name, *exist_oui_name;
	bool flag = true, ret = false;
	int cnt;

	new_oui_argvals = get_oui_name(argvals);
	if (!new_oui_argvals) {
		printf("Incorrect OUI Value, missing comma as delimited for "
		       "OUI Type\n");
		return false;
	}
	new_oui_name = argvals;
	for (cnt = 0; cnt < total_oui; cnt++) {
		if (!oui_data[cnt])
			continue;
		exist_oui_name = oui_data[cnt]->oui_name;
		if (!strncmp(new_oui_name, exist_oui_name,
			     VDP22_OUI_MAX_NAME)) {
			flag = false;
			break;
		}
	}
	if (flag) {
		oui_data[total_oui] = calloc(1, sizeof(vdptool_oui_data_t));
		fill_oui_hdr(oui_data[total_oui], new_oui_name);
		ret = run_vdptool_oui_hndlr(oui_data[total_oui],
					    new_oui_argvals);
	} else
		ret = run_vdptool_oui_hndlr(oui_data[cnt], new_oui_argvals);
	if (!ret)
		return false;
	return flag;
}

int render_cmd(struct cmd *cmd, int argc, char **args, char **argvals)
{
	int len;
	int i;
	int fid = 0, oui = 0;
	vdptool_oui_data_t **oui_data;
	bool is_new;

	len = sizeof(cmd->obuf);

	/* To avoid another loop to figure the number of OUI's */
	oui_data = calloc(argc, sizeof(vdptool_oui_data_t *));
	if (!oui_data) {
		printf("Not enough memory\n");
		return 0;
	}

	if ((cmd->cmd == cmd_settlv) || (cmd->cmd == cmd_gettlv)) {
		for (i = 0; i < argc; i++) {
			if (!args[i])
				continue;
			if (!strncasecmp(args[i], "filter", strlen("filter")))
				fid++;
			else if (!strncasecmp(args[i], "oui", strlen("oui"))) {
				is_new = rewrite_oui_argval(argvals[i],
							    oui_data,
							    oui);
				if (is_new) {
					argvals[i] = oui_data[oui]->data;
					oui++;
				} else {
					args[i] = NULL;
					argvals[i] = NULL;
				}
			}
		}
	}
	cmd->ops |= (fid << OP_FID_POS) | (oui << OP_OUI_POS);
	/* all command messages begin this way */
	snprintf(cmd->obuf, len, "%c%08x%c%1x%02x%08x%02x%s%02x%08x",
		MOD_CMD, cmd->module_id, CMD_REQUEST, CLIF_MSG_VERSION,
		cmd->cmd, cmd->ops, (unsigned int) strlen(cmd->ifname),
		cmd->ifname, cmd->type, cmd->tlvid);
	/* Add any args and argvals to the command message */
	for (i = 0; i < argc; i++) {
		if (args[i])
			snprintf(cmd->obuf + strlen(cmd->obuf),
				 len - strlen(cmd->obuf),
				 "%02x%s", (unsigned int)strlen(args[i]),
				 args[i]);
		if (argvals[i])
			snprintf(cmd->obuf + strlen(cmd->obuf),
				 len - strlen(cmd->obuf), "%04x%s",
				 (unsigned int)strlen(argvals[i]), argvals[i]);
	}
	for (i = 0; i < oui; i++) {
		if (oui_data[i])
			free(oui_data[i]);
	}
	free(oui_data);
	return strlen(cmd->obuf);
}

int vdp_clif_command(struct clif *, char *, int);

static int vdp_cmd_getvsi(struct clif *clif, int argc, char *argv[],
			  struct cmd *cmd, int raw)
{
	int numargs = 0;
	char **args;
	char **argvals;
	int i;

	if (cmd->cmd != cmd_gettlv)
		return cmd_invalid;

	args = calloc(argc, sizeof(char *));
	if (!args)
		return cmd_failed;

	argvals = calloc(argc, sizeof(char *));
	if (!argvals) {
		free(args);
		return cmd_failed;
	}

	for (i = 0; i < argc; i++)
		get_arg_value(argv[i], &args[i], &argvals[i]);
	numargs = i;

	/* Default is local tlv query */
	if (!(cmd->ops & op_neighbor))
		cmd->ops |= op_local;

	if (numargs) {
		/* Only commands with the config option should have arguments.*/
		if (!(cmd->ops & op_config)) {
			printf("%s\n", print_status(cmd_invalid));
			goto out;
		}

		/* Commands to get neighbor TLVs cannot have arguments. */
		if (cmd->ops & op_neighbor) {
			printf("%s\n", print_status(cmd_invalid));
			goto out;
		}
		cmd->ops |= op_arg;
	}

	render_cmd(cmd, argc, args, argvals);
	free(args);
	free(argvals);
	return vdp_clif_command(clif, cmd->obuf, raw);
out:
	free(args);
	free(argvals);
	return cmd_invalid;
}

static int vdp_cmd_setvsi(struct clif *clif, int argc, char *argv[],
			  struct cmd *cmd, int raw)
{
	int numargs = 0;
	char **args;
	char **argvals;
	int i;

	if (cmd->cmd != cmd_settlv)
		return cmd_invalid;
	args = calloc(argc, sizeof(char *));
	if (!args)
		return cmd_failed;

	argvals = calloc(argc, sizeof(char *));
	if (!argvals) {
		free(args);
		return cmd_failed;
	}

	for (i = 0; i < argc; i++)
		get_arg_value(argv[i], &args[i], &argvals[i]);
	numargs = i;

	for (i = 0; i < numargs; i++) {
		if (!argvals[i]) {
			printf("%s\n", print_status(cmd_invalid));
			goto out;
		}
	}

	if (numargs)
		cmd->ops |= (op_arg | op_argval);

	render_cmd(cmd, argc, args, argvals);
	free(args);
	free(argvals);
	return vdp_clif_command(clif, cmd->obuf, raw);
out:
	free(args);
	free(argvals);
	return cmd_invalid;
}

static int hex2u8(char *b)
{
	int hex = -1;

	if (isxdigit(*b) && isxdigit(*(b + 1)))
		sscanf(b, "%02x", &hex);
	return hex;
}

static int hex2u16(char *b)
{
	int hex = -1;

	if (isxdigit(*b) && isxdigit(*(b + 1)) && isxdigit(*(b + 2))
	    && isxdigit(*(b + 3)))
		sscanf(b, "%04x", &hex);
	return hex;
}

static int hex2u32(char *b)
{
	int hex;
	char *b_old = b;

	for (hex = 0; hex < 8; ++hex)
		if (!isxdigit(*b++))
			return -1;
	sscanf(b_old, "%08x", &hex);
	return hex;
}

static int vdp_parse_response(char *buf)
{
	return hex2u8(buf + CLIF_STAT_OFF);
}

void print_vsi_err_msg(char *key_val)
{
	unsigned long errcode;
	int resp_err, smi_err;

	errcode = strtol(key_val, NULL, 10);
	resp_err = errcode & 0xff;
	smi_err = (errcode >> VDP22_STATUS_BITS) & 0xff;

	switch (resp_err) {
	case VDP22_RESP_INVALID_FORMAT:
		printf("\tError returned by Bridge: %s\n",
			VSI22_INVALID_FRMT_ERR_STR);
		break;
	case VDP22_RESP_NO_RESOURCES:
		printf("\tError returned by Bridge: %s\n",
			VSI22_NO_RES_ERR_STR);
		break;
	case VDP22_RESP_NO_VSIMGR:
		printf("\tError returned by Bridge: %s\n",
			VSI22_NO_VSIMGR_ERR_STR);
		break;
	case VDP22_RESP_OTHER:
		printf("\tError returned by Bridge: %s\n", VSI22_OTHER_ERR_STR);
		break;
	case VDP22_RESP_NOADDR:
		printf("\tError returned by Bridge: %s\n",
			VSI22_NOADDR_ERR_STR);
		break;
	case VDP22_RESP_DEASSOC:
		printf("\tError returned by Bridge: %s\n", VSI22_DEASS_ERR_STR);
		break;
	case VDP22_RESP_TIMEOUT:
		printf("\tError returned by Bridge: %s\n",
			VSI22_TIMEOUT_ERR_STR);
		break;
	case VDP22_RESP_KEEP:
		printf("\tError returned by Bridge: %s\n", VSI22_KEEP_ERR_STR);
		break;
	default:
		break;
	}
	if (smi_err & (1 << VDP22_KATO))
		printf("\tInternal Error : %s\n", VSI22_KATO_ERR_STR);
	if (smi_err & (1 << VDP22_ACKTO))
		printf("\tInternal Error : %s\n", VSI22_ACKTO_ERR_STR);
	if (smi_err & (1 << VDP22_TXERR))
		printf("\tInternal Error : %s\n", VSI22_TX_ERR_STR);
}

static void print_oui_vals(char *argvals)
{
	char oui_name[VDP22_OUI_MAX_NAME];
	char *temp_argval = argvals;
	char *oui_val;
	int tbl_size, cnt;
	u8 oui_name_len;

	hexstr2bin(argvals, &oui_name_len, sizeof(oui_name_len));
	if (oui_name_len >= VDP22_OUI_MAX_NAME)
		return;
	temp_argval = argvals + 2 * sizeof(oui_name_len);
	oui_val = temp_argval + oui_name_len;
	strncpy(oui_name, temp_argval, oui_name_len);
	oui_name[oui_name_len] = '\0';
	tbl_size = sizeof(oui_hndlr_tbl) / sizeof(vdptool_oui_hndlr_tbl_t);
	for (cnt = 0; cnt < tbl_size; cnt++) {
		if (!strncmp(oui_hndlr_tbl[cnt].oui_name, oui_name,
			     VDP22_OUI_MAX_NAME))
			oui_hndlr_tbl[cnt].oui_print_decode_hndlr(oui_val);
	}
}

static void print_vsi(char **args, char **argvals, int numargs,
		      bool err_flag)
{
	int i;

	for (i = 0; i < numargs; i++) {
		if (err_flag && (!strcmp(args[i], VSI22_ARG_HINTS_STR)))
			print_vsi_err_msg(argvals[i]);
		else {
			if (!strcmp(args[i], VSI22_ARG_OUI_STR)) {
				print_oui_vals(argvals[i]);
			} else {
				printf("\t%s", args[i]);
				printf(" = %s\n", argvals[i]);
			}
		}
	}
}

int get_vsi_args(char *ibuf, bool print_err_code)
{
	int ioff = 0;
	char **args;
	char **argvals;
	int numargs;
	int ilen = strlen(ibuf);

	/* count args and argvalus */
	numargs = get_vsistr_arg_count(ioff, ilen);

	args = calloc(numargs, sizeof(char *));
	if (!args)
		return cmd_failed;

	argvals = calloc(numargs, sizeof(char *));
	if (!argvals) {
		free(args);
		return cmd_failed;
	}

	numargs = get_arg_val_list(ibuf, ilen, &ioff, args, argvals);
	print_vsi(args, argvals, numargs, print_err_code);

	free(args);
	free(argvals);
	return ioff;
}

static void print_all_vsis(char *ibuf, bool err_code, char *msg)
{
	size_t ilen = strlen(ibuf);
	u16 vsi_len;
	int offset = 0, vsi_cnt = 0;
	char tmp_ibuf[strlen(ibuf)];

	while (ilen > 0) {
		vsi_len = hex2u16(ibuf + offset);
		if (vsi_len > ilen)
			return;
		offset += 2 * sizeof(u16);
		ilen -= 2 * sizeof(u16);
		strncpy(tmp_ibuf, ibuf + offset, vsi_len);
		tmp_ibuf[vsi_len] = '\0';
		if (msg)
			printf("%s\n", msg);
		else
			printf("%s %d:\n", "VSI ", vsi_cnt);
		get_vsi_args(tmp_ibuf, err_code);
		offset += vsi_len;
		ilen -= vsi_len;
		vsi_cnt++;
	}
}

static void print_cmd_response(char *ibuf, int status)
{
	struct cmd cmd;
	unsigned char len;
	int ioff;

	if (status != cmd_success) {
		printf("FAILED: %s\n", print_status(status));
		return;
	}

	cmd.cmd = hex2u8(ibuf + CMD_CODE);
	cmd.ops = hex2u32(ibuf + CMD_OPS);
	len = hex2u8(ibuf + CMD_IF_LEN);
	ioff = CMD_IF;
	if (len < sizeof(cmd.ifname)) {
		memcpy(cmd.ifname, ibuf + CMD_IF, len);
	} else {
		printf("Response ifname too long: %*s\n", (int)len, cmd.ifname);
		return;
	}
	cmd.ifname[len] = '\0';
	ioff += len;

	if (cmd.cmd == cmd_gettlv || cmd.cmd == cmd_settlv) {
		cmd.tlvid = hex2u32(ibuf + ioff);
		ioff += 2 * sizeof(cmd.tlvid);
	}

	switch (cmd.cmd) {
	case cmd_gettlv:
		print_all_vsis(ibuf + ioff, false, NULL);
		break;
	case cmd_settlv:
		printf("%s", ibuf + ioff);
		break;
	default:
		return;
	}
}

static void vdp_print_response(char *buf, int status)
{
	switch (buf[CLIF_RSP_OFF]) {
	case PING_CMD:
		if (status)
			printf("FAILED:%s\n", print_status(status));
		else
			printf("%s\n", buf + CLIF_RSP_OFF + 5);
		break;
	case ATTACH_CMD:
	case DETACH_CMD:
		if (status)
			printf("FAILED:%s\n", print_status(status));
		else
			printf("OK\n");
		break;
	case CMD_REQUEST:
		print_cmd_response(buf + CLIF_RSP_OFF, status);
		break;
	default:
		printf("Unknown VDP command response: %s\n", buf);
		break;
	}
}

static void vdp_print_event_msg(char *buf)
{
	printf("%s buf:%s\n", __func__, buf);
	print_all_vsis(buf + CLIF_RSP_OFF, true, "Response from VDP");
}

/*
 * Dummy function to avoid linkage of many sources
 */
int get_perm_hwaddr(UNUSED const char *ifname, UNUSED unsigned char *buf_perm,
		    UNUSED unsigned char *buf_san)
{
	return -EIO;
}

static int show_raw;

static const char *cli_version =
	"vdptool v" LLDPTOOL_VERSION "\n"
	"Copyright (c) 2014, IBM Corporation\n";


static const char *cli_license =
"This program is free software. You can distribute it and/or modify it\n"
"under the terms of the GNU General Public License version 2.\n"
"\n";
/*
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license. See README and COPYING for more details.\n";
*/

static const char *cli_full_license =
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA\n"
"\n"
"Alternatively, this software may be distributed under the terms of the\n"
"BSD license.\n"
"\n"
"Redistribution and use in source and binary forms, with or without\n"
"modification, are permitted provided that the following conditions are\n"
"met:\n"
"\n"
"1. Redistributions of source code must retain the above copyright\n"
"   notice, this list of conditions and the following disclaimer.\n"
"\n"
"2. Redistributions in binary form must reproduce the above copyright\n"
"   notice, this list of conditions and the following disclaimer in the\n"
"   documentation and/or other materials provided with the distribution.\n"
"\n"
"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
"   names of its contributors may be used to endorse or promote products\n"
"   derived from this software without specific prior written permission.\n"
"\n"
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
"\n";

static const char *commands_usage =
"Usage:\n"
"  vdptool <command> [options] [arg]   general command line usage format\n"
"  vdptool                             go into interactive mode\n"
"          <command> [options] [arg]   general interactive command format\n";

static const char *commands_options =
"Options:\n"
"  -i [ifname]           network interface\n"
"  -V [tlvid]            TLV identifier\n"
"                        may be numeric or keyword (see below)\n"
"  -c <argument list>    used with get TLV command to specify\n"
"                        that the list of configuration elements\n"
"  -n                    \"neighbor\" option for command (To be done)\n"
"  -r                    show raw message\n"
"  -R                    show only raw messages\n";

static const char *commands_help =
"Commands:\n"
"  license    show license information\n"
"  -h|help    show command usage information\n"
"  -v|version show version\n"
"  -p|ping    ping lldpad and query pid of lldpad\n"
"  -q|quit    exit lldptool (interactive mode)\n"
"  -t|get-vsi get VSI association(s)\n"
"  -T|set-vsi set VSI association\n";

static struct clif *clif_conn;
static int cli_quit;
static int cli_attached;

/*
 * insert to head, so first one is last
 */
struct lldp_module *(*register_tlv_table[])(void) = {
	vdp22_cli_register,
	NULL,
};

static void init_modules(void)
{
	struct lldp_module *module;
	struct lldp_module *premod = NULL;
	int i = 0;

	LIST_INIT(&lldp_head);
	for (i = 0; register_tlv_table[i]; i++) {
		module = register_tlv_table[i]();
		if (premod)
			LIST_INSERT_AFTER(premod, module, lldp);
		else
			LIST_INSERT_HEAD(&lldp_head, module, lldp);
		premod = module;
	}
}

void deinit_modules(void)
{
	struct lldp_module *module;

	while (lldp_head.lh_first != NULL) {
		module = lldp_head.lh_first;
		LIST_REMOVE(lldp_head.lh_first, lldp);
		module->ops->lldp_mod_unregister(module);
	}
}

static void usage(void)
{
	fprintf(stderr, "%s\n", cli_version);
	fprintf(stderr, "\n%s\n%s\n%s\n",
		commands_usage, commands_options, commands_help);
}

static void print_raw_message(char *msg, int print)
{
	if (!print || !(print & SHOW_RAW))
		return;

	if (!(print & SHOW_RAW_ONLY)) {
		switch (msg[MSG_TYPE]) {
		case EVENT_MSG:
			printf("event: ");
			break;
		case CMD_RESPONSE:
			printf("rsp: ");
			break;
		default:
			printf("cmd: ");
			break;
		}
	}
	printf("%s\n", msg);
}

static int parse_print_message(char *msg, int print)
{
	int status = 0;

	status = vdp_parse_response(msg);
	print_raw_message(msg, print);
	if (print & SHOW_RAW_ONLY)
		return status;

	if (msg[MSG_TYPE] == CMD_RESPONSE)
		vdp_print_response(msg, status);
	else if (msg[MSG_TYPE] == MOD_CMD && msg[MOD_MSG_TYPE] == EVENT_MSG)
		vdp_print_event_msg(&msg[MOD_MSG_TYPE]);
	return status;
}

static void cli_close_connection(void)
{
	if (clif_conn == NULL)
		return;

	if (cli_attached) {
		clif_detach(clif_conn);
		cli_attached = 0;
	}
	clif_close(clif_conn);
	clif_conn = NULL;
}


static void cli_msg_cb(char *msg, UNUSED size_t len)
{
	parse_print_message(msg, SHOW_OUTPUT | show_raw);
}


/* structure of the print argument bitmap:
 *     SHOW_NO_OUTPUT (0x0) - don't print anything for the command
 *     SHOW_OUTPUT (0x01)   - print output for the command
 *     SHOW_RAW (0x02)      - print the raw clif command messages
 *     SHOW_RAW_ONLY (0x04) - print only the raw clif command messages
*/
static int _clif_command(struct clif *clif, char *cmd, int print)
{
	char buf[MAX_CLIF_MSGBUF];
	size_t len;
	int ret;
	int rc;
	char reply[MAX_CLIF_MSGBUF];
	size_t reply_len2 = sizeof(reply);

	print_raw_message(cmd, print);

	if (clif_conn == NULL) {
		printf("Not connected to lldpad - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = clif_request(clif, cmd, strlen(cmd), buf, &len, cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed with error %s.\n", cmd,
			strerror(errno));
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		ret = parse_print_message(buf, print);
	}
	if (cli_attached) {
		rc = clif_vsievt(clif, reply, &reply_len2, 5);
		if (!rc)
			print_all_vsis(reply, true, "Response from VDP");
	}

	return ret;
}

int vdp_clif_command(struct clif *clif, char *cmd, int raw)
{
	return _clif_command(clif, cmd, SHOW_OUTPUT | raw);
}

static int cli_cmd_ping(struct clif *clif, UNUSED int argc, UNUSED char *argv[],
			UNUSED struct cmd *command, int raw)
{
	return vdp_clif_command(clif, "P", raw);
}

static int
cli_cmd_nop(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
	    UNUSED struct cmd *command, UNUSED int raw)
{
	return 0;
}

static int
cli_cmd_help(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
	     UNUSED struct cmd *command, UNUSED int raw)
{
	struct lldp_module *np;

	printf("%s\n%s\n%s", commands_usage, commands_options, commands_help);

	printf("\nTLV identifiers:\n");
	LIST_FOREACH(np, &lldp_head, lldp)
		if (np->ops->print_help)
			np->ops->print_help();
	return 0;
}

static int
cli_cmd_version(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
		UNUSED struct cmd *command, UNUSED int raw)
{
	printf("%s\n", cli_version);
	return 0;
}

static int
cli_cmd_license(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
		UNUSED struct cmd *command, UNUSED int raw)
{
	printf("%s\n", cli_full_license);
	return 0;
}

static int
cli_cmd_quit(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
	     UNUSED struct cmd *command, UNUSED int raw)
{
	cli_quit = 1;
	return 0;
}

static struct cli_cmd {
	vdp22_cmd cmdcode;
	const char *cmdstr;
	int (*handler)(struct clif *clif, int argc, char *argv[],
		       struct cmd *cmd, int raw);
} cli_commands[] = {
	{ cmd_ping,     "ping",      cli_cmd_ping },
	{ cmd_help,     "help",      cli_cmd_help },
	{ cmd_license,  "license",   cli_cmd_license },
	{ cmd_version,  "version",   cli_cmd_version },
	{ cmd_quit,     "quit",      cli_cmd_quit },
	{ cmd_gettlv,   "getvsi",    vdp_cmd_getvsi },
	{ cmd_gettlv,   "get-vsi",   vdp_cmd_getvsi },
	{ cmd_settlv,   "setvsi",    vdp_cmd_setvsi },
	{ cmd_settlv,   "set-vsi",   vdp_cmd_setvsi },
	{ cmd_nop,       NULL,       cli_cmd_nop }
};

u32 lookup_tlvid(char *tlvid_str)
{
	struct lldp_module *np;
	u32 tlvid = INVALID_TLVID;

	LIST_FOREACH(np, &lldp_head, lldp) {
		if (np->ops->lookup_tlv_name) {
			tlvid = np->ops->lookup_tlv_name(tlvid_str);
			if (tlvid != INVALID_TLVID)
				break;
		}
	}

	return tlvid;
}

void print_args(int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++)
		printf("\tremaining arg %d = %s\n", i, argv[i]);
}

static struct option lldptool_opts[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{"stats", 0, NULL, 'S'},
	{"get-vsi", 0, NULL, 't'},
	{"set-vsi", 0, NULL, 'T'},
	{"get-lldp", 0, NULL, 'l'},
	{"set-lldp", 0, NULL, 'L'},
	{0, 0, 0, 0}
};

static int request(struct clif *clif, int argc, char *argv[])
{
	struct cli_cmd *cmd, *match = NULL;
	struct cmd command;
	int count;
	int ret	= 0;
	int newraw = 0;
	int numargs = 0;
	char **argptr = &argv[0];
	char *end;
	char attach_str[9] = "";
	int c;
	int option_index;

	memset((void *)&command, 0, sizeof(command));
	command.cmd = cmd_nop;
	command.type = NEAREST_CUSTOMER_BRIDGE;
	command.module_id = LLDP_MOD_VDP22;
	command.tlvid = INVALID_TLVID;

	opterr = 0;
	for (;;) {
		c = getopt_long(argc, argv, "i:tTWhcnvrRpqV:",
				lldptool_opts, &option_index);
		if (c < 0)
			break;
		switch (c) {
		case '?':
			printf("missing argument for option %s\n\n",
			       argv[optind-1]);
			usage();
			return -1;
		case 'i':
			strncpy(command.ifname, optarg, IFNAMSIZ);
			command.ifname[IFNAMSIZ] = '\0';
			break;
		case 'V':
			if (command.tlvid != INVALID_TLVID) {
				printf("\nInvalid command: multiple TLV identifiers: %s\n",
				       optarg);
				return -1;
			}

			/* Currently tlvid unset lookup and verify parameter */
			errno = 0;
			command.tlvid = strtoul(optarg, &end, 0);
			if (!command.tlvid || errno || *end != '\0' ||
			    end == optarg)
				command.tlvid = lookup_tlvid(optarg);
			if (command.tlvid == INVALID_TLVID) {
				printf("\nInvalid TLV identifier: %s\n",
					optarg);
				return -1;
			}
			break;
		case 'p':
			command.cmd = cmd_ping;
			break;
		case 'q':
			command.cmd = cmd_quit;
			break;
		case 't':
			command.cmd = cmd_gettlv;
			break;
		case 'T':
			command.cmd = cmd_settlv;
			break;
		case 'c':
			command.ops |= op_config;
			break;
		case 'n':
			command.ops |= op_neighbor;
			break;
		case 'h':
			command.cmd = cmd_help;
			break;
		case 'r':
			if (newraw) {
				usage();
				return -1;
			}
			newraw = SHOW_RAW;
			break;
		case 'R':
			if (newraw) {
				usage();
				return -1;
			}
			newraw = (SHOW_RAW | SHOW_RAW_ONLY);
			break;
		case 'v':
			command.cmd = cmd_version;
			break;
		case 'W':
			snprintf(attach_str, sizeof(attach_str), "%x",
				LLDP_MOD_VDP22);
			if (clif_attach(clif, attach_str) != 0) {
				printf("Warning: Failed to attach to lldpad.\n");
				return -1;
			}
			cli_attached = 1;
			break;
		default:
			usage();
			ret = -1;
		}
	}

	/* if no command was supplied via an option flag, then
	 * the first remaining argument should be the command.
	 */
	count = 0;
	if (command.cmd == cmd_nop && optind < argc) {
		cmd = cli_commands;
		while (cmd->cmdcode != cmd_nop) {
			if (strncasecmp(cmd->cmdstr, argv[optind],
			    strlen(argv[optind])) == 0) {
				match = cmd;
				command.cmd = match->cmdcode;
				count++;
			}
			cmd++;
		}
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:",
			argv[optind]);
		cmd = cli_commands;
		while (cmd->cmdstr) {
			if (strncasecmp(cmd->cmdstr, argv[optind],
			    strlen(argv[optind])) == 0)
				printf(" %s", cmd->cmdstr);
			cmd++;
		}
		printf("\n");
		ret = -1;
	} else {
		if (!match) {
			cmd = cli_commands;
			while (cmd->cmdcode != command.cmd)
				cmd++;
			match = cmd;
		}
		numargs = argc-optind - count;
		if (numargs)
			argptr = &argv[argc-numargs];
		ret = match->handler(clif, numargs, argptr, &command, newraw);
	}
	return ret;
}

static void cli_recv_pending(struct clif *clif, int in_read)
{
	int first = 1;

	if (clif == NULL)
		return;
	while (clif_pending(clif)) {
		char buf[256];
		size_t len = sizeof(buf) - 1;
		if (clif_recv(clif, buf, &len) == 0) {
			buf[len] = '\0';
			if (in_read && first)
				printf("\n");
			first = 0;
			cli_msg_cb(buf, len);
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}
}

static char *do_readline(const char *prompt)
{
	size_t	size = 0;
	ssize_t	rc;
	char	*line = NULL;

	fputs(prompt, stdout);
	fflush(stdout);

	rc = getline(&line, &size, stdin);
	if (rc <= 0)
		return NULL;
	if (line[rc - 1] == '\n')
		line[rc - 1] = 0;
	return line;
}

static void cli_interactive(void)
{
	const int max_args = 20;
	char *cmd, *argv[max_args], *pos;
	int argc;

	setlinebuf(stdout);
	printf("\nInteractive mode\n\n");
	do {
		cli_recv_pending(clif_conn, 0);
		alarm(1);
		cmd = do_readline("> ");
		alarm(0);
		if (!cmd)
			break;
		argc = 1;
		pos = cmd;
		for (;;) {
			while (*pos == ' ')
				pos++;
			if (*pos == '\0')
				break;
			argv[argc] = pos;
			argc++;
			if (argc == max_args)
				break;
			while (*pos != '\0' && *pos != ' ')
				pos++;
			if (*pos == ' ')
				*pos++ = '\0';
		}
		if (argc) {
			optind = 0;
			request(clif_conn, argc, argv);
		}
		free(cmd);
	} while (!cli_quit);
}

static void cli_terminate(UNUSED int sig)
{
	cli_close_connection();
	exit(0);
}

static void cli_alarm(UNUSED int sig)
{
	if (clif_conn && _clif_command(clif_conn, "P", SHOW_NO_OUTPUT)) {
		printf("Connection to lldpad lost - trying to reconnect\n");
		cli_close_connection();
	}
	if (!clif_conn) {
		clif_conn = clif_open();
		if (clif_conn) {
			char attach_str[9] = "";
			u32 mod_id = LLDP_MOD_VDP22;
			bin2hexstr((u8 *)&mod_id, 4, attach_str, 8);
			printf("Connection to lldpad re-established\n");
			if (clif_attach(clif_conn, attach_str) == 0)
				cli_attached = 1;
			else
				printf("Warning: Failed to attach to lldpad.\n");
		}
	}
	if (clif_conn)
		cli_recv_pending(clif_conn, 1);
	alarm(1);
}


int main(int argc, char *argv[])
{
	int interactive = 1;
	int warning_displayed = 0;
	int ret = 0;

	if (argc > 1)
		interactive = 0;
	if (interactive)
		printf("%s\n\n%s\n\n", cli_version, cli_license);
	for (;;) {
		clif_conn = clif_open();
		if (clif_conn) {
			if (warning_displayed)
				printf("Connection established.\n");
			break;
		}

		if (!interactive) {
			perror("Failed to connect to lldpad - clif_open");
			return -1;
		}

		if (!warning_displayed) {
			printf("Could not connect to lldpad - re-trying\n");
			warning_displayed = 1;
		}
		sleep(1);
	}

	init_modules();
	signal(SIGINT, cli_terminate);
	signal(SIGTERM, cli_terminate);
	signal(SIGALRM, cli_alarm);

	if (interactive) {
		char attach_str[9] = "";
		u32 mod_id = LLDP_MOD_VDP22;
		bin2hexstr((u8 *)&mod_id, 4, attach_str, 8);
		if (clif_attach(clif_conn, attach_str) == 0)
			cli_attached = 1;
		else
			printf("Warning: Failed to attach to lldpad.\n");
		cli_interactive();
	} else {
		ret = request(clif_conn, argc, &argv[0]);
		ret = !!ret;
	}
	cli_close_connection();
	deinit_modules();
	return ret;
}
