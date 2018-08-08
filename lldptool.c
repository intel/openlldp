/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software 
  Copyright(c) 2007-2012 Intel Corporation.

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

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "clif.h"
#include "lldp_mand_clif.h"
#include "lldp_basman_clif.h"
#include "lldp_med_clif.h"
#include "lldp_8023_clif.h"
#include "lldp_dcbx_clif.h"
#include "lldp_evb22_clif.h"
#include "lldp_evb_clif.h"
#include "qbg_vdp_clif.h"
#include "lldp_8021qaz_clif.h"
#include "lldp_orgspec_clif.h"
#include "lldp_cisco_clif.h"
#include "lldptool.h"
#include "lldptool_cli.h"
#include "lldp_mod.h"
#include "lldp_mand.h"
#include "lldp_basman.h"
#include "lldp_med.h"
#include "lldp_dcbx.h"
#include "version.h"
#include "lldpad.h"
#include "lldp_util.h"
#include "lldpad_status.h"

static int show_raw;

static const char *cli_version =
"lldptool v" LLDPTOOL_VERSION "\n"
"Copyright (c) 2007-2010, Intel Corporation\n"
"\nSubstantially modified from:  hostapd_cli v 0.5.7\n"
"Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi> and contributors";


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
"  lldptool <command> [options] [arg]   general command line usage format\n"
"  lldptool                             go into interactive mode\n"
"           <command> [options] [arg]   general interactive command format\n";

static const char *commands_options =
"Options:\n"
"  -i [ifname]                          network interface\n"
"  -V [tlvid]                           TLV identifier\n"
"                                       may be numeric or keyword (see below)\n"
"  -c <argument list>                   used with get TLV command to specify\n"
"                                       that the list of configuration elements\n"
"                                       should be retrieved\n"
"  -d                                   use to delete specified argument from\n"
"                                       the configuration.  (Currently\n"
"                                       implemented for DCBX App TLV settings)\n"
"  -n                                   \"neighbor\" option for command\n"
"  -r                                   show raw message\n"
"  -R                                   show only raw messages\n"
"  -g					destination agent (may be one of):\n"
"						- nearestbridge (nb) (default)\n"
"						- nearestcustomerbridge (ncb)\n"
"						- nearestnontpmrbridge (nntpmrb)\n";

static const char *commands_help =
"Commands:\n"
"  license                              show license information\n"
"  -h|help                              show command usage information\n"
"  -v|version                           show version\n"
"  -p|ping                              ping lldpad and query pid of lldpad\n"
"  -q|quit                              exit lldptool (interactive mode)\n"
"  -S|stats                             get LLDP statistics for ifname\n"
"  -t|get-tlv                           get TLVs from ifname\n"
"  -T|set-tlv                           set arg for tlvid to value\n"
"  -l|get-lldp                          get the LLDP parameters for ifname\n"
"  -L|set-lldp                          set the LLDP parameter for ifname\n";

static struct clif *clif_conn;
static int cli_quit = 0;
static int cli_attached = 0;

/*
 * insert to head, so first one is last
 */
struct lldp_module *(*register_tlv_table[])(void) = {
	mand_cli_register,
	basman_cli_register,
	ieee8023_cli_register,
	med_cli_register,
	dcbx_cli_register,
	evb22_cli_register,
	evb_cli_register,
	vdp_cli_register,
	ieee8021qaz_cli_register,
	orgspec_cli_register,
	cisco_cli_register,
	NULL,
};

static void init_modules(void)
{
	struct lldp_module *module;
	struct lldp_module *premod = NULL;
	int i = 0;

	LIST_INIT(&lldp_cli_head);
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

void print_raw_message(char *msg, int print)
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

int parse_print_message(char *msg, int print)
{
	int status = 0;

	status = parse_response(msg);

	print_raw_message(msg, print);

	if (print & SHOW_RAW_ONLY)
		return status;

	if (msg[MSG_TYPE] == CMD_RESPONSE)
		print_response(msg, status);
	else if (msg[MSG_TYPE] == MOD_CMD && msg[MOD_MSG_TYPE] == EVENT_MSG)
		print_event_msg(&msg[MOD_MSG_TYPE]);

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

	print_raw_message(cmd, print);

	if (clif_conn == NULL) {
		printf("Not connected to lldpad - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = clif_request(clif, cmd, strlen(cmd), buf, &len,
			       cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		ret = parse_print_message(buf, print);
	}

	return ret;
}


inline int clif_command(struct clif *clif, char *cmd, int raw)
{
	return _clif_command(clif, cmd, SHOW_OUTPUT | raw);
}

static int cli_cmd_ping(struct clif *clif, UNUSED int argc, UNUSED char *argv[],
			UNUSED struct cmd *command, int raw)
{
	return clif_command(clif, "P", raw);
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

struct cli_cmd {
	lldp_cmd cmdcode;
	const char *cmdstr;
	int (*handler)(struct clif *clif, int argc, char *argv[],
		       struct cmd *cmd, int raw);
};

static struct cli_cmd cli_commands[] = {
	{ cmd_ping,     "ping",      cli_cmd_ping },
	{ cmd_help,     "help",      cli_cmd_help },
	{ cmd_license,  "license",   cli_cmd_license },
	{ cmd_version,  "version",   cli_cmd_version },
	{ cmd_quit,     "quit",      cli_cmd_quit },
	{ cmd_getstats, "stats",     cli_cmd_getstats },
	{ cmd_gettlv,   "gettlv",    cli_cmd_gettlv },
	{ cmd_gettlv,   "get-tlv",   cli_cmd_gettlv },
	{ cmd_settlv,   "settlv",    cli_cmd_settlv },
	{ cmd_settlv,   "set-tlv",   cli_cmd_settlv },
	{ cmd_get_lldp, "getlldp",   cli_cmd_getlldp },
	{ cmd_get_lldp, "get-lldp",  cli_cmd_getlldp },
	{ cmd_set_lldp, "setlldp",   cli_cmd_setlldp },
	{ cmd_set_lldp, "set-lldp",  cli_cmd_setlldp },
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
	{"get-tlv", 0, NULL, 't'},
	{"set-tlv", 0, NULL, 'T'},
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
	int c;
	int option_index;

	memset((void *)&command, 0, sizeof(command));
	command.cmd = cmd_nop;
	command.type = NEAREST_BRIDGE;
	command.module_id = LLDP_MOD_MAND;
	command.tlvid = INVALID_TLVID;

	opterr = 0;
	for (;;) {
		c = getopt_long(argc, argv, "Si:tTlLhcdnvrRpqV:g:",
				lldptool_opts, &option_index);
		if (c < 0)
			break;
		switch (c) {
		case '?':
			printf("missing argument for option %s\n\n", argv[optind-1]);
			usage();
			return -1;
		case 'S':
			command.cmd = cmd_getstats;
			break;
		case 'i':
			strncpy(command.ifname, optarg, IFNAMSIZ);
			command.ifname[IFNAMSIZ] ='\0';
			break;
		case 'g':
			if (!strcasecmp(optarg, "nearestbridge") ||
			    !strcasecmp(optarg, "nearest_bridge") ||
			    !strcasecmp(optarg, "nb"))
				command.type = NEAREST_BRIDGE;
			else if (!strcasecmp(optarg, "nearestcustomerbridge") ||
				 !strcasecmp(optarg, "nearest_customer_bridge") ||
				 !strcasecmp(optarg, "ncb"))
				command.type = NEAREST_CUSTOMER_BRIDGE;
			else if (!strcasecmp(optarg, "nearestnontpmrbridge") ||
				 !strcasecmp(optarg, "nearest_nontpmr_bridge") ||
				 !strcasecmp(optarg, "nntpmrb"))
				command.type = NEAREST_NONTPMR_BRIDGE;
			else {
				printf("Invalid agent specified !\n\n");
				return -1;
			}
			break;
		case 'V':
			if (command.tlvid != INVALID_TLVID) {
				printf("\nInvalid command: multiple TLV "
				       "identifiers: %s\n", optarg);
				return -1;
			}

			/* Currently tlvid unset lookup and verify parameter */
			errno = 0;
			command.tlvid = strtoul(optarg, &end, 0);

			if (!command.tlvid || errno || *end != '\0' ||
			    end == optarg) {
				command.tlvid = lookup_tlvid(optarg);
				if (!strcasecmp("vdp", optarg))
					command.module_id = command.tlvid;
			}

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
		case 'l':
			command.cmd = cmd_get_lldp;
			break;
		case 'L':
			command.cmd = cmd_set_lldp;
			break;
		case 'c':
			command.ops |= op_config;
			break;
		case 'd':
			command.ops |= op_delete;
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
		default:
			usage();
			ret = -1;
		}
	}
	/*
	 * If -V vdp option is set together with -c option, use standard
	 * module to retrieve data.
	 */
	if ((command.ops & op_config) && command.tlvid == command.module_id)
		command.module_id = LLDP_MOD_MAND;

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

		if (count == 0)
			numargs = argc-optind;
		else
			numargs = argc-optind-1;

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


static void cli_interactive()
{
	const int max_args = 20;
	char *cmd, *argv[max_args], *pos;
	int argc;

	setlinebuf(stdout);
	printf("\nInteractive mode\n\n");
	using_history();
	stifle_history(1000);

	do {
		cli_recv_pending(clif_conn, 0);
		alarm(1);
		cmd = readline("> ");
		alarm(0);
		if (!cmd)
			break;
		if (*cmd)
			add_history(cmd);
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
			u32 mod_id = LLDP_MOD_MAND;
			bin2hexstr((u8*)&mod_id, 4, attach_str, 8);
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
		continue;
	}

	init_modules();

	signal(SIGINT, cli_terminate);
	signal(SIGTERM, cli_terminate);
	signal(SIGALRM, cli_alarm);

	if (interactive) {
		char attach_str[9] = "";
		u32 mod_id = LLDP_MOD_MAND;
		bin2hexstr((u8*)&mod_id, 4, attach_str, 8);
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
