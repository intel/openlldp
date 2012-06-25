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

%option nounput
%option noinput

%{
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "lldp_dcbx_cmds.h"
#include "dcb_types.h"
#include "parse_cli.h"
#define BADARG "bad argument: "

static int cmd=0;
static int feature=0;
static int subtype=0;
static int error=0;
static char *port_id = NULL;
static char *badarg = NULL;
static int got_args = 0;
static int dcb_state = -1;
static int dcbx_version = -1;
static int advertise = 0x0f;
static int enable = 0x0f;
static int willing = 0x0f;
static int up2tc_a[MAX_USER_PRIORITIES];
static int up2tc_idx = 0;
static int pgpct_a[MAX_BANDWIDTH_GROUPS];
static int pgpct_idx = 0;
static int pgid_a[MAX_USER_PRIORITIES];
static int pgid_idx = 0;
static int uppct_a[MAX_USER_PRIORITIES];
static int uppct_idx = 0;
static int strict_a[MAX_USER_PRIORITIES];
static int strict_idx = 0;
static int pfcup_a[MAX_USER_PRIORITIES];
static int pfcup_idx = 0;
static int appsubtype = -1;
static char *appcfg_p = NULL;
static int llsubtype = -1;
static int llstatus = -1;
static int desc_id = 0;
static char *desc_str = NULL;
static int fargs = 0;
%}

%option noyywrap
%x dcb
%x dcbx
%x pg
%x pfc
%x app
%x ll

%x up2tc
%x pgpct
%x pgid
%x uppct
%x strict

%x getport
%x getfeature
%x getdcbargs
%x getdcbxargs
%x getdcbxver
%x getpfcargs
%x getpgargs
%x getpgdescargs
%x getpgdesc
%x getappargs
%x getllargs

%x getadvertise
%x getenable
%x getwilling
%x getup2tc
%x getpgpct
%x getpgid
%x getuppct
%x getstrict
%x getpfcup
%x getappsubtype
%x getappcfg
%x getllsubtype
%x getllstatus

%x cmddone

%%

[ \\t]+

gc	{ if (!cmd) {
		cmd = CMD_GET_CONFIG;
	} else {
		if (!badarg) badarg = strdup(yytext);
		error = 1;
	}
	BEGIN(getport);
	}

sc	{ if (!cmd) {
		cmd = CMD_SET_CONFIG;
	} else {
		if (!badarg) badarg = strdup(yytext);
		error = 1;
	}
	BEGIN(getport);
	}

go	{ if (!cmd) {
		cmd = CMD_GET_OPER;
	} else {
		if (!badarg) badarg = strdup(yytext);
		error = 1;
	}
	BEGIN(getport);
	}

gp	{ if (!cmd) {
		cmd = CMD_GET_PEER;
	} else {
		if (!badarg) badarg = strdup(yytext);
		error = 1;
	}
	BEGIN(getport);
	}

[[:alnum:][:punct:][:cntrl:]]+	{ if (!badarg) badarg = strdup(yytext);
					error = 1;
				}

<getport>[ \\t]
<getport>dcbx			{ feature = FEATURE_DCBX;
				/* 'dcbx' is a global feature which does not
				 * require a port name.
				*/
				if (cmd == CMD_SET_CONFIG) {
					BEGIN(getdcbxargs);
				} else if (cmd != CMD_GET_PEER) {
					BEGIN(cmddone);
				} else {
					error = 1;
					if (!badarg) badarg =
						strdup("invalid command");
				}
				}
				
<getport>[a-zA-Z0-9_.:-]+	{ port_id = strdup(yytext);
				BEGIN(getfeature);
				}


<getfeature>[ \\t]
<getfeature>dcb			{ feature = FEATURE_DCB;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getdcbargs);
				else
					BEGIN(cmddone);
				}

<getfeature>pfc			{ feature = FEATURE_PFC;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getpfcargs);
				else
					BEGIN(cmddone);
				}

<getfeature>pg			{ feature = FEATURE_PG;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getpgargs);
				else
					BEGIN(cmddone);
				}

<getfeature>pgdesc		{ feature = FEATURE_PG_DESC;
				BEGIN(getpgdescargs);
				}

<getfeature>app			{ feature = FEATURE_APP;
				BEGIN(getappsubtype);
				}
<getfeature>ll          	{ feature = FEATURE_LLINK;
				BEGIN(getllsubtype);
				}
				
<getfeature>[a-zA-Z0-9]+	{
				if (!badarg) badarg = strdup(yytext);
				error = 1;
				}

<getdcbxargs>[ \\t]

<getdcbxargs>v:			{
				BEGIN(getdcbxver);
				}

<getdcbxver>[1256]		{ dcbx_version = atoi(yytext);
				BEGIN(cmddone);
				}

<getdcbxver>cee			{ dcbx_version = dcbx_subtype2;
				BEGIN(cmddone);
				}

<getdcbxver>cin			{ dcbx_version = dcbx_subtype1;
				BEGIN(cmddone);
				}

<getdcbxver>force-cee		{ dcbx_version = dcbx_force_subtype2;
				BEGIN(cmddone);
				}

<getdcbxver>force-cin		{ dcbx_version = dcbx_force_subtype1;
				BEGIN(cmddone);
				}

<getdcbargs,getpgargs,getpfcargs,getappargs,getpgdescargs>[ \\t]

<getdcbargs>on			{ dcb_state = 1;
				BEGIN(cmddone);
				}

<getdcbargs>off			{ dcb_state = 0;
				BEGIN(cmddone);
				}

<getpgdescargs>[1-8]		{
				desc_id = *yytext & 0x0f;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getpgdesc);
				else
					BEGIN(cmddone);
				}

<getpgdesc>[ \\t]+

<getpgdesc>[[:alnum:][:punct:]]+[[:alnum:][:punct:] \\t]+[[:alnum:][:punct:]]+	{
				desc_str = strdup(yytext);
				BEGIN(cmddone);
				}

<getpgdesc>[[:cntrl:]]		{
				error = 1;
				if (!badarg) badarg = strdup(yytext);
				}

<getpgargs,getpfcargs,getappargs,getllargs>a: {
				if (got_args & GOT_ADVERTISE) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_ADVERTISE;
					BEGIN(getadvertise);
				}
				}

<getpgargs,getpfcargs,getappargs,getllargs>e: {
				if (got_args & GOT_ENABLE) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_ENABLE;
					BEGIN(getenable);
				}
				}

<getpgargs,getpfcargs,getappargs,getllargs>w: {
				if (got_args & GOT_WILLING) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_WILLING;
					BEGIN(getwilling);
				}
				}

<getadvertise>[01]		{ advertise = atoi(yytext);
				switch (feature) {
				case FEATURE_PG: BEGIN(getpgargs); break;
				case FEATURE_PFC: BEGIN(getpfcargs); break;
				case FEATURE_APP: BEGIN(getappargs); break;
				case FEATURE_LLINK: BEGIN(getllargs); break;
				default:
					if (!badarg) badarg =
						strdup("invalid feature");
					error = 1;
				}
				}

<getenable>[01]			{ enable = atoi(yytext);
				switch (feature) {
				case FEATURE_PG: BEGIN(getpgargs); break;
				case FEATURE_PFC: BEGIN(getpfcargs); break;
				case FEATURE_APP: BEGIN(getappargs); break;
				case FEATURE_LLINK: BEGIN(getllargs); break;
				default:
					if (!badarg) badarg =
						strdup("invalid feature");
					error = 1;
				}
				}

<getwilling>[01]		{ willing = atoi(yytext);
				switch (feature) {
				case FEATURE_PG: BEGIN(getpgargs); break;
				case FEATURE_PFC: BEGIN(getpfcargs); break;
				case FEATURE_APP: BEGIN(getappargs); break;
				case FEATURE_LLINK: BEGIN(getllargs); break;
				default:
					if (!badarg) badarg =
						strdup("invalid feature");
					error = 1;
				}
				}

<getwilling,getenable,getadvertise>[2-9[:alpha:][:punct:][:cntrl:] \\t]	{
				error = 1;
				if (!badarg) badarg = strdup(yytext);
				}

<getpgargs>up2tc:		{
				if (got_args & GOT_UP2TC) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_UP2TC;
					BEGIN(getup2tc);
				}
				}

<getpgargs>pgpct:		{
				if (got_args & GOT_PGPCT) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_PGPCT;
					BEGIN(getpgpct);
				}
				}

<getpgargs>pgid:		{
				if (got_args & GOT_PGID) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_PGID;
					BEGIN(getpgid);
				}
				}

<getpgargs>uppct:		{
				if (got_args & GOT_UPPCT) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_UPPCT;
					BEGIN(getuppct);
				}
				}

<getpgargs>strict:		{
				if (got_args & GOT_STRICT) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_STRICT;
					BEGIN(getstrict);
				}
				}

<getpfcargs>pfcup:		{
				if (got_args & GOT_PFCUP) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_PFCUP;
					BEGIN(getpfcup);
				}
				}

<getappsubtype>:[0-9]+		{ appsubtype = atoi(yytext+1);
				if (appsubtype >= DCB_MAX_APPTLV) {
					appsubtype = -1;
					if (!badarg) badarg =
						strdup("invalid subtype");
					error = 1;
				}
				else if (cmd == CMD_SET_CONFIG) {
					BEGIN(getappargs);
				}
				else
					BEGIN(cmddone);
				}

<getappsubtype>:[fF][cC][oO][eE][ \\t]		{ appsubtype = 0;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getappargs);
				else
					BEGIN(cmddone);
				}

<getappsubtype>:[iI][sS][cC][sC][iI][ \\t]	{ appsubtype = 1;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getappargs);
				else
					BEGIN(cmddone);
				}

<getappargs>appcfg:		{
				if (got_args & GOT_APPCFG) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_APPCFG;
					BEGIN(getappcfg);
				}
				}

<getllsubtype>:0		{ llsubtype = atoi(yytext+1);
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getllargs);
				else
					BEGIN(cmddone);
				}

<getllsubtype>:[fF][cC][oO][eE][ \\t]		{ llsubtype = 0;
				if (cmd == CMD_SET_CONFIG)
					BEGIN(getllargs);
				else
					BEGIN(cmddone);
				}

<getllargs>status:		{
				if (got_args & GOT_LLSTATUS) {
					if (!badarg) badarg =
						strdup("duplicate argument");
					error = 1;
				} else {
					got_args |= GOT_LLSTATUS;
					BEGIN(getllstatus);
				}
				}

<getllstatus>[01]		{ llstatus = atoi(yytext);
				BEGIN(getllargs);
				}

<getdcbargs,getpfcargs,getpgargs,getappargs,getpgdescargs>[[:alnum:][:punct:][:cntrl:]]	{
					BEGIN(cmddone);
					yyless(0);
					}

<getup2tc>[0-7]			{ up2tc_a[up2tc_idx++] = atoi(yytext);
				if (up2tc_idx == 8) {
					BEGIN(getpgargs);
				}
				}

<getpgpct,getuppct>[, \\t]+
<getpgpct>[0-9]+		{ pgpct_a[pgpct_idx] = atoi(yytext);
				if (pgpct_a[pgpct_idx] > 100) {
					if (!badarg) badarg =
						strdup("invalid percent value");
					error = 1;
				} else {
					pgpct_idx++;
					if (pgpct_idx == 8) {
						BEGIN(getpgargs);
					}
				}
				}

<getuppct>[0-9]+		{ uppct_a[uppct_idx] = atoi(yytext);
				if (uppct_a[uppct_idx] > 100) {
					if (!badarg) badarg =
						strdup("invalid percent value");
					error = 1;
				} else {
					uppct_idx++;
					if (uppct_idx == 8) {
						BEGIN(getpgargs);
					}
				}
				}

<getpgpct,getuppct>[a-zA-Z0-9]+	{ BEGIN(getpgargs);
					}

<getpgid>[0-7fF]		{ pgid_a[pgid_idx++] = strtol(yytext, NULL, 16);
				if (pgid_idx == 8) {
					BEGIN(getpgargs);
				}
				}

<getstrict>[01]			{ strict_a[strict_idx++] = atoi(yytext);
				if (strict_idx == 8) {
					BEGIN(getpgargs);
				}
				}

<getpfcup>[01]			{ pfcup_a[pfcup_idx++] = atoi(yytext);
				if (pfcup_idx == 8) {
					BEGIN(getpfcargs);
				}
				}

<getappcfg>[0-9a-fA-F]{2}	{ appcfg_p = strdup(yytext);
					BEGIN(getappargs);
				}

<getappcfg,getup2tc,getpgpct,getpgid,getuppct,getstrict,getpfcup,getdcbxargs,getdcbxver,getappsubtype,getllsubtype>.	{
				error = 1;
				if (!badarg) badarg = strdup(yytext);
				}

<cmddone>[^[:blank:]]+		{ if (!badarg) badarg = strdup(yytext);
					error = 1;
				}

<<EOF>>				{
				BEGIN(INITIAL);
				yyterminate();
				}
%%


int get_port_len()
{
	if (port_id)
		return strlen(port_id);
	else
		return 0;
}

int *get_up2tc()
{
	return &up2tc_a[0];
}

int *get_pgpct()
{
	return &pgpct_a[0];
}

int *get_pgid()
{
	return &pgid_a[0];
}

int *get_uppct()
{
	return &uppct_a[0];
}

int *get_strict()
{
	return &strict_a[0];
}

int *get_pfcup()
{
	return &pfcup_a[0];
}

char *get_appcfg()
{
	return appcfg_p;
}
int get_enable()
{
	return enable;
}

int get_dcb_param()
{
	return dcb_state;
}

int get_dcbx_param()
{
	return dcbx_version;
}

int get_advertise()
{
	return advertise;
}

int get_willing()
{
	return willing;
}

int get_cmd()
{
	return cmd;
}

int get_fargs()
{
	return fargs;
}

int get_feature()
{
	return feature;
}

int get_subtype()
{
	return subtype;
}

int get_desc_id()
{
	return desc_id;
}

char *get_desc_str()
{
	return desc_str;
}

void free_desc_str()
{
	if (desc_str) {
		free(desc_str);
		desc_str = NULL;
	}
}

char *get_port()
{
	return port_id;
}

int get_llstatus()
{
	return llstatus;
}

void free_port()
{
	if (port_id) {
		free(port_id);
		port_id = NULL;
	}
}

void free_appcfg()
{
	if (appcfg_p) {
		free(appcfg_p);
		appcfg_p = NULL;
	}
}

char *get_parse_error()
{
	return badarg;
}

void free_parse_error()
{
	if (badarg) {
		free(badarg);
		badarg = NULL;
	}
}

void init_parse_state()
{
	cmd=0;
	feature=0;
	error=0;
	free_parse_error();
	free_port();
	free_appcfg();
	free_desc_str();
	dcb_state = -1;
	dcbx_version = -1;
	advertise = 0xf;
	enable = 0xf;
	willing = 0xf;
	up2tc_idx = 0;
	pgpct_idx = 0;
	pgid_idx = 0;
	uppct_idx = 0;
	strict_idx = 0;
	pfcup_idx = 0;
	appsubtype = -1;
	llsubtype = -1;
	llstatus = -1;
	desc_id = 0;
	got_args = 0;
	fargs = 0;
}

int parse_dcb_cmd(char *buf)
{
	int i;
	int pargs = 1;
	YY_BUFFER_STATE yyhnd;

	yyout = fopen("/dev/null", "a+");
	yyhnd = yy_scan_string(buf);
	yylex();
	yy_delete_buffer(yyhnd);

	if (error) {
		return error;
	}

	switch (cmd) {
	case CMD_GET_CONFIG:
	case CMD_GET_OPER:
	case CMD_GET_PEER:
		if (!feature) {
			if (!badarg)
				badarg = strdup("feature was not specified");
			error = 1;
		}

		if (!port_id && feature != FEATURE_DCBX) {
			if (!badarg)
				badarg = strdup("port was not specified");
			error = 1;
		}

		switch (feature) {
		case FEATURE_DCB:
		case FEATURE_DCBX:
			if (cmd == CMD_GET_PEER) {
				if (!badarg)
					badarg = strdup("invalid command");
				error = 1;
				break;
			}
			/* else fall thru */
		case FEATURE_PG:
		case FEATURE_PFC:
			subtype = 0;
			break;
		case FEATURE_APP:
			if (appsubtype >= 0) {
				subtype = appsubtype;
			} else {
				subtype = 0;
				if (!badarg)
					badarg = strdup("subtype was not "
							"specified");
				error = 1;
			}
			break;

		case FEATURE_LLINK:
			if (llsubtype >= 0) {
				subtype = llsubtype;
			} else {
				subtype = 0;
				if (!badarg)
					badarg = strdup("subtype was not "
							"specified");
				error = 1;
			}
			break;

		case FEATURE_PG_DESC:
			if (!desc_id) {
				desc_id = 0;
				if (!badarg)
					badarg = strdup("pgid was not "
							"specified");
				error = 1;
			}
			if (cmd != CMD_GET_CONFIG) {
				if (!badarg)
					badarg = strdup("invalid command");
				error = 1;
			}
			subtype = 0;
			break;

		default:
			if (!badarg)
				badarg = strdup("invalid feature");
			error = 1;
			break;
		}
		break;

	case CMD_SET_CONFIG:
		if (!port_id && feature != FEATURE_DCBX) {
			if (!badarg)
				badarg = strdup("port was not specified");
			error = 1;
			break;
		}

		/* make sure all command components were provided */
		if (advertise == 0x0f && willing == 0x0f && enable == 0x0f) {
			pargs = 0;
		}

		switch (feature) {
		case FEATURE_DCB:
			fargs = (dcb_state > -1);
			if (fargs == 0) {
				if (!badarg)
					badarg = strdup("no dcb arg supplied");
				error = 1;
			}
			break;
		case FEATURE_DCBX:
			fargs = (dcbx_version > -1);
			if (fargs == 0) {
				if (!badarg)
					badarg = strdup("no dcbx arg supplied");
				error = 1;
			}
			break;
		case FEATURE_PG:

			/* check if pg attributes were included and flag error
			 * if an incomplete set was entered.
			 */
			fargs = up2tc_idx + strict_idx + pgpct_idx +
				uppct_idx + pgid_idx;

			if (fargs == 0 && pargs == 0) {
				if (!badarg)
					badarg = strdup("no pg args supplied");
				error = 1;
				break;
			}

			if (up2tc_idx == 0) {
				for (i = 0; i < MAX_USER_PRIORITIES; i++)
					if (fargs)
						up2tc_a[i] = -1;
			}
			else if (up2tc_idx < MAX_USER_PRIORITIES) {
				if (!badarg)
					badarg = strdup("incomplete up2tc "
							"argument");
				error = 1;
				break;
			}

			if (pgid_idx == 0) {
				for (i = 0; i < MAX_USER_PRIORITIES; i++)
					if (fargs)
						pgid_a[i] = -1;
			}
			else if (pgid_idx < MAX_USER_PRIORITIES) {
				if (!badarg)
					badarg = strdup("incomplete pgid "
							"argument");
				error = 1;
				break;
			}

			if (pgpct_idx == 0) {
				for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++)
					if (fargs)
						pgpct_a[i] = -1;
			}
			else if (pgpct_idx < MAX_BANDWIDTH_GROUPS) {
				if (!badarg)
					badarg = strdup("incomplete pgpct "
							"argument");
				error = 1;
				break;
			}

			if (uppct_idx == 0) {
				for (i = 0; i < MAX_USER_PRIORITIES; i++)
					if (fargs)
						uppct_a[i] = -1;
			}
			else if (uppct_idx < MAX_USER_PRIORITIES) {
				if (!badarg)
					badarg = strdup("incomplete uppct "
							"argument");
				error = 1;
				break;
			}

			if (strict_idx == 0) {
				for (i=0; i<MAX_USER_PRIORITIES; i++) {
					if (fargs)
						strict_a[i] = -1;
				}
			}
			else if (strict_idx < MAX_USER_PRIORITIES) {
				if (!badarg)
					badarg = strdup("incomplete strict "
							"argument");
				error = 1;
				break;
			}
			break;

		case FEATURE_PFC:  /* pfc */
			fargs = pfcup_idx;
			if (fargs == 0 && pargs == 0) {
				if (!badarg)
					badarg = strdup("no pfc args supplied");
				error = 1;
				break;
			}

			if (pfcup_idx && pfcup_idx < MAX_USER_PRIORITIES) {
				if (!badarg)
					badarg = strdup("incomplete pfcup "
							"argument");
				error = 1;
			}

			break;

		case FEATURE_APP:
			fargs = (appcfg_p != NULL);
			if (fargs == 0 && pargs == 0) {
				if (!badarg)
					badarg = strdup("no app args supplied");
				error = 1;
				break;
			}

			if (appcfg_p && strlen(appcfg_p) % 2) {
				if (!badarg)
					badarg = strdup("invalid appcfg "
							"length");
				error = 1;
				break;
			}

			subtype = appsubtype;

			if (!appcfg_p)
				break;

			switch (appsubtype) {
			case APP_FCOE_STYPE:
				if (strlen(appcfg_p) != 2) {
					if (!badarg)
						badarg = strdup("invalid appcfg"
							" length for FCoE");
					error = 1;
				}
				break;
			case APP_ISCSI_STYPE:
				if (strlen(appcfg_p) != 2) {
					if (!badarg)
						badarg = strdup("invalid appcfg"
							" length for iSCSI");
					error = 1;
				}
				break;
			default:
				break;
			}
			break;

		case FEATURE_LLINK:
			if (pargs == 0 && llstatus < 0) {
				if (!badarg)
					badarg = strdup("no args supplied");
				error = 1;
				break;
			}
			break;

		case FEATURE_PG_DESC:
			fargs = (desc_str != NULL);

			if (fargs == 0) {
				if (!badarg)
					badarg = strdup("bwg description was "
							"not supplied");
				error = 1;
				break;
			}

			if (desc_str && strlen(desc_str) >=
				MAX_DESCRIPTION_LEN) {
				if (!badarg)
					badarg = strdup("bwg description "
						"length too long (max 99)");
				error = 1;
			}

			break;
		default:
			if (!badarg)
				badarg = strdup("invalid feature");
			error = 1;
			break;
		}

		break;

	default:
		badarg = strdup("invalid DCB command");
		error = 1;
	}

	return error;
}
