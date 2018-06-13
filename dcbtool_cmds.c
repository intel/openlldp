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

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "clif.h"
#include "dcbtool.h"
#include "lldp_dcbx_cmds.h"
#include "lldpad_status.h"
#include "dcb_types.h"
#include "parse_cli.h"
#include "messages.h"
#include "lldp_util.h"

static char *print_status(cmd_status status);
static char *get_pgdesc_args(int cmd);
static void free_cmd_args(char *args);
static char *get_dcb_args(void);
static char *get_dcbx_args(void);
static char *get_pg_args(void);
static char *get_pfc_args(void);
static char *get_app_args(void);
static char *get_ll_args(void);
static char *get_cmd_args(void);
static void print_errors(int errors);

static const char *hexlist = "0123456789ABCDEF";

static char *print_status(cmd_status status)
{
	char *str;

	switch(status) {
	case cmd_success:
		str = "Successful";
		break;
	case cmd_failed:
		str = "Failed";
		break;
	case cmd_device_not_found:
		str = "Device not found, link down or DCB not enabled";
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
		str = "Command not applicable in IEEE-DCBX modes";
		break;
	case cmd_no_access:
		str = "Access denied";
		break;
	default:
		str = "Unknown status";
		break;
	}
	return str;
}

static char *get_dcb_args(void)
{
	char buf[8];
	int j;
	
	j = 0;

	if (get_fargs())
		buf[j++] = hexlist[get_dcb_param() & 0x0f];

	buf[j]=0;

	return strdup(buf);
}

static char *get_dcbx_args(void)
{
	char buf[8];
	int j;
	
	j = 0;

	if (get_fargs())
		buf[j++] = hexlist[get_dcbx_param() & 0x0f];

	buf[j]=0;

	return strdup(buf);
}

static char *get_pgdesc_args(int cmd)
{
	char buf[MAX_DESCRIPTION_LEN + 8];
	char *p;
	int j;
	
	j = 0;
	
	sprintf(buf+j, "%01x", get_desc_id());
	j++;

	if (cmd == CMD_SET_CONFIG) {
		p = get_desc_str();
		if (p != NULL && strlen(p) < MAX_DESCRIPTION_LEN - 1) {
			sprintf(buf+j, "%02x", (unsigned int) strlen(p));
			j+=2;
			memcpy(buf+j, p, strlen(p));
			j += strlen(p);
		}
	}

	buf[j] = 0;

	return strdup(buf);
}

static char *get_pg_args(void)
{
	char buf[256];
	int *aptr;
	int i;
	int j;
	
	j = 0;
	buf[j++] = hexlist[get_enable() & 0x0f];
	buf[j++] = hexlist[get_advertise() & 0x0f];
	buf[j++] = hexlist[get_willing() & 0x0f];

	if (get_fargs()) {
		aptr = get_up2tc();
		for (i=0; i<MAX_USER_PRIORITIES; i++)
			if (aptr[i] >= 0)
				buf[j++] = hexlist[aptr[i] & 0x0f];
			else
				buf[j++] = CLIF_NOT_SUPPLIED;

		aptr = get_pgpct();
		for (i=0; i<MAX_BANDWIDTH_GROUPS; i++) {
			if (aptr[i] >= 0) {
				buf[j++] = hexlist[(aptr[i] & 0xf0)>>4];
				buf[j++] = hexlist[aptr[i] & 0x0f];
			} else {
				buf[j++] = CLIF_NOT_SUPPLIED;
				buf[j++] = CLIF_NOT_SUPPLIED;
			}
		}

		aptr = get_pgid();
		for (i=0; i<MAX_USER_PRIORITIES; i++)
			if (aptr[i] >= 0)
				buf[j++] = hexlist[aptr[i] & 0x0f];
			else
				buf[j++] = CLIF_NOT_SUPPLIED;

		aptr = get_uppct();
		for (i=0; i<MAX_USER_PRIORITIES; i++) {
			if (aptr[i] >= 0) {
				buf[j++] = hexlist[(aptr[i] & 0xf0)>>4];
				buf[j++] = hexlist[aptr[i] & 0x0f];
			} else {
				buf[j++] = CLIF_NOT_SUPPLIED;
				buf[j++] = CLIF_NOT_SUPPLIED;
			}
		}
			
		aptr = get_strict();
		for (i=0; i<MAX_USER_PRIORITIES; i++)
			if (aptr[i] >= 0)
				buf[j++] = hexlist[aptr[i] & 0x0f];
			else
				buf[j++] = CLIF_NOT_SUPPLIED;

		/* num tc field - not used by set yet */
		buf[j++] = CLIF_NOT_SUPPLIED;
	}

	buf[j]=0;

	return strdup(buf);
}

static char *get_pfc_args(void)
{
	char buf[256];
	int *aptr;
	int i;
	int j;
	
	j = 0;
	buf[j++] = hexlist[get_enable() & 0x0f];
	buf[j++] = hexlist[get_advertise() & 0x0f];
	buf[j++] = hexlist[get_willing() & 0x0f];

	if (get_fargs()) {
		aptr = get_pfcup();
		for (i=0; i<MAX_USER_PRIORITIES; i++)
			if (aptr[i] >= 0)
				buf[j++] = hexlist[aptr[i] & 0x0f];
			else
				buf[j++] = CLIF_NOT_SUPPLIED;

		/* num tc field - not used by set yet */
		buf[j++] = CLIF_NOT_SUPPLIED;
	}

	buf[j] = 0;

	return strdup(buf);
}

static char *get_app_args(void)
{
	char buf[512];
	char *p;
	int j;
	
	j = 0;
	buf[j++] = hexlist[get_enable() & 0x0f];
	buf[j++] = hexlist[get_advertise() & 0x0f];
	buf[j++] = hexlist[get_willing() & 0x0f];

	p = get_appcfg();
	if (p != NULL && strlen(p) < sizeof(buf)-5) {
		sprintf(buf+j, "%02x", (unsigned int)strlen(p));
		j+=2;
		memcpy(buf+j, p, strlen(p));
		j += strlen(p);
	}

	buf[j] = 0;

	return strdup(buf);
}

static char *get_ll_args(void)
{
	char buf[8];
	int j;
	int n;
	
	j = 0;
	buf[j++] = hexlist[get_enable() & 0x0f];
	buf[j++] = hexlist[get_advertise() & 0x0f];
	buf[j++] = hexlist[get_willing() & 0x0f];

	n = get_llstatus();
	if (n < 0)
		buf[j++] = CLIF_NOT_SUPPLIED;
	else
		buf[j++] = hexlist[n];

	buf[j++] = 0;

	return strdup(buf);
}


static char *get_cmd_args(void)
{
	char *args = NULL;

	switch (get_cmd()) {
	case CMD_GET_CONFIG:
	case CMD_GET_OPER:
	case CMD_GET_PEER:
		switch (get_feature()) {
		case FEATURE_PG_DESC:
			args = get_pgdesc_args(CMD_GET_CONFIG);
			break;
		default:
			/* query commands without arguments */
			args = strdup("");
			break;
		}
		break;

	case CMD_SET_CONFIG:
		switch (get_feature()) {
		case FEATURE_DCB:
			args = get_dcb_args();
			break;
		case FEATURE_DCBX:
			args = get_dcbx_args();
			break;
		case FEATURE_PG:
			args = get_pg_args();
			break;
		case FEATURE_PFC:
			args = get_pfc_args();
			break;
		case FEATURE_APP:
			args = get_app_args();
			break;
		case FEATURE_LLINK:
			args = get_ll_args();
			break;
		case FEATURE_PG_DESC:
			args = get_pgdesc_args(CMD_SET_CONFIG);
			break;
		default:
			args = strdup("");
			printf("warning: unknown feature\n");
		break;
		}
		break;
	default:
		args = strdup("");
		printf("warning: unknown cmd\n");
	}

	return args;
}

static void free_cmd_args(char *args)
{
	if (args)
		free(args);
}

int handle_dcb_cmds(struct clif *clif, int argc, char *argv[], int raw)
{
	char cbuf[MAX_CLIF_MSGBUF];
	char buf[MAX_CLIF_MSGBUF];
	char *cmd_args;
	int i;

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < argc; i++)
		snprintf(buf + strlen(buf), sizeof(buf)-strlen(buf),
			"%s ", argv[i]);

	init_parse_state();
	if (parse_dcb_cmd(buf)) {
		printf("invalid command argument: %s\n", get_parse_error());
		free_parse_error();
		return -1;
	}

	cmd_args = get_cmd_args();

	if (get_feature() == FEATURE_DCBX)
		snprintf(cbuf, sizeof(cbuf), "%c%01x%02x%02x%s",
			DCB_CMD, CLIF_MSG_VERSION,
			get_cmd(), get_feature(), cmd_args);
	else
		snprintf(cbuf, sizeof(cbuf), "%c%01x%02x%02x%02x%02x%s%s",
			DCB_CMD, CLIF_MSG_VERSION,
			get_cmd(), get_feature(), get_subtype(), get_port_len(),
			get_port(), cmd_args);

	free_cmd_args(cmd_args);
		
	return clif_command(clif, cbuf, raw);
}

void print_errors(int errors)
{
	int flag = 0;

	printf("0x%02x - ", errors);

	if (!errors) {
		printf("none\n");
		return;
	}

	if (errors & 0x01) {
		flag++;
		printf("mismatch with peer");
	}

	if (errors & 0x02) {
		if (flag++)
			printf(", ");
		printf("local configuration error");
	}

	if (errors & 0x04) {
		if (flag++)
			printf(", ");
		printf("multiple TLV's received");
	}

	if (errors & 0x08) {
		if (flag++)
			printf(", ");
		printf("peer error");
	}

	if (errors & 0x10) {
		if (flag++)
			printf(", ");
		printf("multiple LLDP neighbors");
	}

	if (errors & 0x20) {
		if (flag++)
			printf(", ");
		printf("peer feature not present");
	}

	printf("\n");
}

void print_dcb_cmd_response(char *buf, int status)
{
	int version;
	int dcb_cmd;
	int feature;
	int dcbx_st = DCBX_SUBTYPE1;
	int subtype = 0;
	int plen = 0;
	int doff;
	int i;
	int n;

	version = buf[DCB_VER_OFF] & 0x0f;
	dcb_cmd = hex2int(buf+DCB_CMD_OFF);
	feature = hex2int(buf+DCB_FEATURE_OFF);
	if (feature == FEATURE_DCBX) {
		doff = DCBX_CFG_OFF;
	} else {
		subtype = hex2int(buf+DCB_SUBTYPE_OFF);
		plen = hex2int(buf+DCB_PORTLEN_OFF);
		doff = DCB_PORT_OFF + plen;
	}

	if (version != CLIF_MSG_VERSION) {
		printf("Unsupported client interface message version: %d\n",
			version);
		return;
	}
	printf("Command:   \t");
	switch(dcb_cmd) {
	case CMD_GET_CONFIG:	
		printf("Get Config\n");
		break;
	case CMD_SET_CONFIG:	
		printf("Set Config\n");
		break;
	case CMD_GET_OPER:	
		printf("Get Oper\n");
		break;
	case CMD_GET_PEER:	
		printf("Get Peer\n");
		break;
	default:
		printf("Unknown DCB command: %d:%s\n", dcb_cmd, buf);
		return;
	}

	printf("Feature:   \t");
	switch (feature) {
	case FEATURE_DCB:
		printf("DCB State\n");
		break;
	case FEATURE_DCBX:
		printf("DCBX Version\n");
		break;
	case FEATURE_PG:
		printf("Priority Groups\n");
		break;
	case FEATURE_PFC:
		printf("Priority Flow Control\n");
		break;
	case FEATURE_APP:
		printf("Application ");
		switch (subtype) {
		case APP_FCOE_STYPE:
			printf("FCoE\n");
			break;
		case APP_ISCSI_STYPE:
			printf("iSCSI\n");
			break;
		case APP_FIP_STYPE:
			printf("FIP\n");
			break;
		default:
			printf("unknown\n");
			break;
		}
		break;

	case FEATURE_LLINK:
		printf("Logical Link ");
		switch (subtype) {
		case LLINK_FCOE_STYPE:
			printf("FCoE\n");
			break;
		default:
			printf("unknown\n");
			break;
		}
		break;

	case FEATURE_PG_DESC:
		printf("BWG Desc\n");
		break;
	default:
		printf("unknown DCB feature: %s\n", buf);
		return;
	}

	if (feature != FEATURE_DCBX)
		printf("Port:      \t%*.*s\n", plen, plen, buf+DCB_PORT_OFF);

	printf("Status:    \t%s\n", print_status(status));

	/* print out data */
	if (dcb_cmd == CMD_SET_CONFIG) /* set command - we're done */
		return;

	if (status != cmd_success) /* set command - we're done */
		return;

	switch(dcb_cmd) {
	case CMD_GET_CONFIG:
		switch(feature) {
		case FEATURE_PG:
		case FEATURE_PFC:
		case FEATURE_APP:
		case FEATURE_LLINK:
			printf("Enable:    \t%s\n",
				(*(buf+doff+CFG_ENABLE) == '1')?
				("true"):("false"));	
			printf("Advertise: \t%s\n",
				(*(buf+doff+CFG_ADVERTISE) == '1')?
				("true"):("false"));
			printf("Willing:   \t%s\n",
				(*(buf+doff+CFG_WILLING) == '1')?
				("true"):("false"));	
			doff += CFG_LEN;
			break;
		default:
			break;
		}
		break;

	case CMD_GET_OPER:
		if (feature == FEATURE_DCBX)
			break;
		printf("Oper Version:\t%d\n", hex2int(buf+doff+OPER_OPER_VER));
		printf("Max Version:\t%d\n", hex2int(buf+doff+OPER_MAX_VER));
		printf("Errors:     \t");
		print_errors(hex2int(buf+doff+OPER_ERROR));
		printf("Oper Mode: \t%s\n", (*(buf+doff+OPER_OPER_MODE) == '1')?
			("true"):("false"));	
		printf("Syncd:     \t%s\n", (*(buf+doff+OPER_SYNCD) == '1')?
			("true"):("false"));	
		doff += OPER_LEN;
		break;

	case CMD_GET_PEER:
		printf("Enable:    \t%s\n", (*(buf+doff+PEER_ENABLE) == '1')?
			("true"):("false"));	
		printf("Willing:   \t%s\n", (*(buf+doff+PEER_WILLING) == '1')?
			("true"):("false"));	
		printf("Oper Version:\t%d\n", hex2int(buf+doff+PEER_OPER_VER));
		printf("Max Version:\t%d\n", hex2int(buf+doff+PEER_MAX_VER));
		printf("Error:     \t%s\n", (*(buf+doff+PEER_ERROR) == '1')?
			("true"):("false"));	
		dcbx_st = (*(buf+doff+PEER_SUBTYPE)) & 0x0f;
		printf("DCBX Subtype:\t%d\n", dcbx_st);
		doff += PEER_LEN;
		break;
	default:
		printf("Unknown DCB command: %d:%s\n", dcb_cmd, buf);
		return;
	}

	switch (feature) {
	case FEATURE_DCB:
		printf("DCB State:\t%s\n",
		      (*(buf+doff+DCB_STATE) == '1')?("on"):("off"));	
		break;
	case FEATURE_DCBX:
		printf("DCBX Version:\t");
		switch (*(buf+doff+DCBX_VERSION) ^ '0') {
		case DCBX_SUBTYPE1:
			printf("CIN\n");
			break;
		case DCBX_SUBTYPE2:
			printf("CEE\n");
			break;
		case DCBX_FORCE_SUBTYPE1:
			printf("FORCED CIN\n");
			break;
		case DCBX_FORCE_SUBTYPE2:
			printf("FORCED CEE\n");
			break;
		default:
			printf("unknown version\n");
			break;
		}
		break;
	case FEATURE_PG_DESC:
		printf("PGID:       \t%d\n", *(buf+doff+PG_DESC_PGID) & 0x0f);
		printf("Description:\t%*s\n",
			hex2int(buf+doff+PG_DESC_LEN),
			buf+doff+PG_DESC_DATA);
		break;
	case FEATURE_PG:

		if (dcb_cmd != CMD_GET_PEER) {
			printf("up2tc:     \t");
			for (i=0; i<MAX_USER_PRIORITIES; i++)
				printf("%c\t", *(buf+doff+PG_UP2TC(i)));
			printf("\n");
		}

		printf("pgpct:     \t");
		for (i=0; i<MAX_BANDWIDTH_GROUPS; i++) {
			n = hex2int(buf+doff+PG_PG_PCNT(i));
			printf("%d%%\t", n);
		}
		printf("\n");

		printf("pgid:      \t");
		for (i=0; i<MAX_USER_PRIORITIES; i++)

			printf("%c\t", *(buf+doff+PG_UP_PGID(i)));
		printf("\n");

		if ((dcb_cmd != CMD_GET_PEER) ||
			(dcb_cmd == CMD_GET_PEER && dcbx_st == DCBX_SUBTYPE1)) {
			printf("uppct:     \t");
			for (i=0; i<MAX_USER_PRIORITIES; i++) {
				n = hex2int(buf+doff+PG_UP_PCNT(i));
				printf("%d%%\t", n);
			}
			printf("\n");

			printf("pg strict: \t");
			for (i=0; i<MAX_USER_PRIORITIES; i++)
				printf("%c\t", *(buf+doff+PG_UP_STRICT(i)));

			printf("\n");
		}

		if (CLIF_NOT_SUPPLIED != *(buf+doff+PG_UP_NUM_TC)) {
			printf("num TC's:  \t%c", *(buf+doff+PG_UP_NUM_TC));
			printf("\n");
		}
		break;
	case FEATURE_PFC:
		printf("pfcup:     \t");
		for (i=0; i<MAX_USER_PRIORITIES; i++)
			printf("%c\t", *(buf+doff+PFC_UP(i)));

		printf("\n");

		if (CLIF_NOT_SUPPLIED != *(buf+doff+PFC_NUM_TC)) {
			printf("num TC's:  \t%c", *(buf+doff+PFC_NUM_TC));
			printf("\n");
		}
		break;
	case FEATURE_APP:
		switch (subtype) {
		case APP_FCOE_STYPE:
		case APP_ISCSI_STYPE:
		case APP_FIP_STYPE:
			printf("appcfg:     \t");
			n = hex2int(buf+doff+APP_LEN);
			printf("%*.*s\n", n, n, buf+doff+APP_DATA);
			break;
		default:
			printf("unknown subtype for ");
			break;
		}
		break;
	case FEATURE_LLINK:
		switch (subtype) {
		case LLINK_FCOE_STYPE:
			printf("Link status: \t");
			printf("%s\n", (*(buf+doff+LLINK_STATUS) == '1')?
				("up"):("down"));	
			break;
		default:
			printf("unknown subtype for ");
			break;
		}
		break;
	default:
		printf("unknown DCB feature: %s\n", buf);
		return;
	}
}

int parse_response(char *buf)
{
	return hex2int(buf+CLIF_STAT_OFF);
}

void print_response(char *buf, int status)
{
	switch(buf[CLIF_RSP_OFF]) {
	case PING_CMD:
		if (status)
			printf("FAILED:%s\n", print_status(status));
		else
			printf("%s\n", buf+CLIF_RSP_OFF);
		break;
	case ATTACH_CMD:
	case DETACH_CMD:
	case LEVEL_CMD:
		if (status)
			printf("FAILED:%s\n", print_status(status));
		else
			printf("OK\n");
		break;
	case DCB_CMD:
		print_dcb_cmd_response(buf+CLIF_RSP_OFF, status);
		break;
	default:
		printf("Unknown DCB command response: %s\n", buf);
	}

	return;
}

void print_event_msg(char *buf)
{
	int level;
	int plen;
	int feature;
	int subtype;

	printf("\nEvent Message\n");

	level = buf[EV_LEVEL_OFF] & 0x0f;

	printf("Level:    \t");
	switch (level) {
	case MSG_MSGDUMP:
		printf("DUMP\n");
		break;
	case MSG_DEBUG:
		printf("DEBUG\n");
		break;
	case MSG_INFO:
		printf("INFO\n");
		break;
	case MSG_WARNING:
		printf("WARNING\n");
		break;
	case MSG_ERROR:
		printf("ERROR\n");
		break;
	case MSG_EVENT:
		printf("DCB EVENT\n");
		break;
	default:
		printf("Unknown event message: %d", level);
		return;
	}

	if (level != MSG_EVENT) {
		printf("Message:  \t%s\n\n", buf+EV_GENMSG_OFF);
		return;
	}

	printf("Version:  \t%c\n", buf[EV_VERSION_OFF]);
	if ((buf[EV_VERSION_OFF] & 0x0f) != CLIF_EV_VERSION) {
		printf("Unsupported Event Message version: %c\n",
			buf[EV_VERSION_OFF]);
		return;
	}
	plen = hex2int(buf+EV_PORT_LEN_OFF);
	printf("Port:    \t%*.*s\n", plen, plen, buf+EV_PORT_ID_OFF);
	
	printf("Feature:  \t");
	feature = hex2int(buf + EV_PORT_ID_OFF + plen + EV_FEATURE_OFF);
	subtype = hex2int(buf + EV_PORT_ID_OFF + plen + EV_SUBTYPE_OFF);
	switch (feature) {
	case FEATURE_DCB:
		printf("DCB Enable\n");
		break;
	case FEATURE_DCBX:
		printf("DCBX Version\n");
		break;
	case FEATURE_PG:
		printf("Priority Groups\n");
		break;
	case FEATURE_PFC:
		printf("Priority Flow Control\n");
		break;
	case FEATURE_APP:
		printf("Application:");
		switch (subtype) {
		case 0:
			printf("FCoE\n");
			break;
		default:
			printf("unknown\n");
			break;
		}
		break;
	case FEATURE_LLINK:
		printf("Logical link:");
		switch (subtype) {
		case 0:
			printf("FCoE\n");
			break;
		default:
			printf("unknown\n");
			break;
		}
		break;
	default:
		printf("unknown DCB feature: %d\n\n", feature);
		return;
	}

	printf("Oper Mode: \t%s\n",
		(*(buf + EV_PORT_ID_OFF + plen + EV_OP_MODE_CHG_OFF) == '1')
			? CHANGED : NOCHANGE);
	printf("Oper Config\t%s\n",
		(*(buf + EV_PORT_ID_OFF + plen + EV_OP_CFG_CHG_OFF) == '1')
			? CHANGED : NOCHANGE);

	printf("\n");
}

