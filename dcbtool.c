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
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "clif.h"
#include "lldp_dcbx_cmds.h"
#include "clif_msgs.h"
#include "lldpad.h"
#include "dcbtool.h"
#include "version.h"

#define UNUSED __attribute__((__unused__))

static int show_raw;

static const char *cli_version =
"dcbtool v" DCBTOOL_VERSION "\n"
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

static const char *commands_help =
"DCBX Commands:\n"
"  <gc|go> dcbx                 get configured or operational DCBX versions\n"
"                               the configured version takes effect on next\n"
"                               restart of the lldpad service\n"
"  sc dcbx v:cee                set the DCBX version to be used after next\n"
"          v:cin                lldpad restart.  Version can be set to:\n"
"          v:force-cin          cin: fall back to CIN DCBX if non-IEEE peer\n"
"          v:force-cee          cee: fall back to CEE DCBX if non-IEEE peer\n"
"                               force-cin, force-cee: do not start with IEEE DCBX\n"
"Per Port Commands:\n"
"  gc <ifname> <feature>        get configuration of <feature> on port <ifname>\n"
"  go <ifname> <feature>        get operational status of <feature>\n"
"                               on port <ifname>\n"
"  gp <ifname> <feature>        get peer configuration of <feature>\n"
"                               on port <ifname>\n"
"  sc <ifname> <feature> <args> general form of set feature configuration\n\n"
"  'feature' can be:\n"
"     dcb                       DCB state of port\n"
"     pg                        priority groups\n"
"     pfc                       priority flow control\n"
"     app:<subtype>             application specific data\n"
"     ll:<subtype>              logical link status\n\n"
"  'subtype' can be:\n"
"     [0|fcoe]                  FCoE\n\n"
"     [1|iscsi]                 iSCSI\n\n"
"     [2|fip]                   FIP\n\n"
"  'args' can include:\n"
"     [e:<0|1>]                 controls feature enable\n"
"     [a:<0|1>]                 controls feature advertise via DCBX\n"
"     [w:<0|1>]                 controls feature DCBX willing mode\n"
"     [feature specific args]   arguments specific to a feature\n\n"
"  feature specific arguments for 'dcb':\n"
"     [on|off]                  the 'dcb' configuration does not use the\n"
"                               enable, advertise or willing mode parameters\n"
"                               'dcb' also does not use the 'go' or 'gp'\n"
"                               commands.\n\n"
"  feature specific arguments for 'pg':\n"
"     [pgid:xxxxxxxx]           priority group ID of user priority.\n"
"                               From left to right (priorities 0-7), x is\n"
"                               the corresponding priority group value\n"
"                               0-7 (for priority groups with bandwidth)\n"
"                               or 'f' (the no bandwidth allocation group)\n"
"     [pgpct:x,x,x,x,x,x,x,x]   priority group percent of link.\n"
"                               From left to right (priority groups 0-7),\n"
"                               x is the percentage of link bandwidth\n"
"                               assigned. The total must equal 100%.\n"
"     [uppct:x,x,x,x,x,x,x,x]   user priority percent of bandwidth group.\n"
"                               From left to right (priorities 0-7),\n"
"                               x is the percentage of priority group\n"
"                               bandwidth assigned to the priority.\n"
"                               The sum of percentages for priorities in the\n"
"                               same priority group must be 100.\n"
"     [strict:xxxxxxxx]         strict priority setting.\n"
"                               From left to right (priorities 0-7),\n"
"                               x is 0 or 1.  1 indicates that the priority\n"
"                               may utilize all of the bandwidth allocated\n"
"                               to its priority group.\n"
"     [up2tc:xxxxxxxx]          user priority to traffic class mapping.\n"
"                               From left to right (priorities 0-7), x is\n"
"                               a the corresponding traffic class (0-7)\n"
"                               (this argument is currently ignored).\n\n"
"  feature specific arguments for 'pfc':\n"
"     [pfcup:xxxxxxxx]          enable/disable priority flow control.\n"
"                               From left to right (priorities 0-7),\n"
"                               x is 0 or 1.  1 indicates that the priority\n"
"                               is configured to transmit priority pause.\n\n"
"  feature specific arguments for 'app:<subtype>':\n"
"     [appcfg:xx]               'xx' is a hexadecimal value representing an\n"
"                               8 bit bitmap where 1 bits indicate the\n"
"                               priority which frames for the application\n"
"                               specified by the subtype should use.\n"
"                               The lowest order bit maps to priority 0.\n\n"
"  feature specific arguments for 'll:<subtype>':\n"
"     [status:<0|1>]            for testing, the logical link status may\n"
"                               be set to 0 or 1.  This setting is not\n"
"                               persisted.\n\n"
"  help                         show command information\n"
"  license                      show license information\n";

static struct clif *clif_conn;
static int cli_quit = 0;
static int cli_attached = 0;


static void usage(void)
{
	fprintf(stderr, "%s\n", cli_version);
	fprintf(stderr, 
		"\n"	
		"Usage:\n"
		"  dcbtool -h\n"
		"  dcbtool -v\n"
		"  dcbtool [-rR] [ command ]\n"
		"  dcbtool                      interactive mode\n"
		"\n"
		"Options:\n"
		"  -h                           help (show this usage text)\n"
		"  -v                           shown version information\n"
		"  -r                           show raw messages\n"
		"  -R                           show only raw messages\n"
		"%s",
		commands_help);
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
	else if (msg[MSG_TYPE] == EVENT_MSG)
		print_event_msg(msg);

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
			int raw)
{
	return clif_command(clif, "P", raw);
}

static int
cli_cmd_help(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
	     UNUSED int raw)
{
	printf("%s", commands_help);
	return 0;
}

static int
cli_cmd_license(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
		UNUSED int raw)
{
	printf("%s\n\n%s\n", cli_version, cli_full_license);
	return 0;
}

static int
cli_cmd_quit(UNUSED struct clif *clif, UNUSED int argc, UNUSED char *argv[],
	     UNUSED int raw)
{
	cli_quit = 1;
	return 0;
}


struct cli_cmd {
	const char *cmd;
	int (*handler)(struct clif *clif, int argc, char *argv[], int raw);
};

static struct cli_cmd cli_commands[] = {
	{ "ping", cli_cmd_ping },
	{ "help", cli_cmd_help },
	{ "license", cli_cmd_license },
	{ "quit", cli_cmd_quit },
	{ NULL, NULL }
};


static int request(struct clif *clif, int argc, char *argv[], int raw)
{
	struct cli_cmd *cmd, *match = NULL;
	int count;
	int ret	= 0;

	count = 0;
	cmd = cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
			    0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
		ret = -1;
	} else if (count == 0) {
		ret = handle_dcb_cmds(clif, argc, &argv[0], raw);
	} else {
		ret = match->handler(clif, argc - 1, &argv[1], raw);
	}

	return ret;	
}


static void cli_recv_pending(struct clif *clif, int in_read)
{
	int first = 1;
	if (clif_conn == NULL)
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

static void cli_interactive(int raw)
{
	const int max_args = 10;
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
		argc = 0;
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
		if (argc)
			request(clif_conn, argc, argv, raw);
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
			printf("Connection to lldpad re-established\n");
			if (clif_attach(clif_conn, NULL) == 0)
				cli_attached = 1;
			else
				printf(
				      "Warning: Failed to attach to lldpad.\n");
		}
	}
	if (clif_conn)
		cli_recv_pending(clif_conn, 1);
	alarm(1);
}


int main(int argc, char *argv[])
{
	int interactive;
	int raw = 0;
	int warning_displayed = 0;
	int c;
	int ret = 0;

	for (;;) {
		c = getopt(argc, argv, "hvrR");
		if (c < 0)
			break;
		switch (c) {
		case 'h':
			usage();
			return 0;
		case 'r':
			if (raw) {
				usage();
				return -1;
			}
			raw = SHOW_RAW;
			break;
		case 'R':
			if (raw) {
				usage();
				return -1;
			}
			raw = (SHOW_RAW | SHOW_RAW_ONLY);
			break;
		case 'v':
			printf("%s\n", cli_version);
			return 0;
		default:
			usage();
			return -1;
		}
	}
	show_raw = raw;

	interactive = argc == optind;

	if (interactive) {
		printf("%s\n\n%s\n\n", cli_version,
		       cli_license);
	}

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

	signal(SIGINT, cli_terminate);
	signal(SIGTERM, cli_terminate);
	signal(SIGALRM, cli_alarm);

	if (interactive) {
		if (clif_attach(clif_conn, NULL) == 0)
			cli_attached = 1;
		else
			printf("Warning: Failed to attach to lldpad.\n");
		cli_interactive(raw);
	} else
		ret = request(clif_conn, argc - optind, &argv[optind], raw);

	cli_close_connection();
	return ret;
}
