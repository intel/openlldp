/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software 
  Copyright(c) 2007-2010 Intel Corporation.

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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "eloop.h"
#include "lldpad.h"
#include "event_iface.h"
#include "messages.h"
#include "version.h"
#include "lldp/ports.h"
#include "lldp/l2_packet.h"
#include "lldp_mand.h"
#include "lldp_basman.h"
#include "lldp_dcbx.h"
#include "lldp_med.h"
#include "lldp_8023.h"
#include "lldp_evb.h"
#include "lldp_evb22.h"
#include "qbg_ecp22.h"
#include "qbg_vdp.h"
#include "qbg_vdp22.h"
#include "lldp_8021qaz.h"
#include "config.h"
#include "lldpad_shm.h"
#include "lldp/agent.h"
#include "lldp/l2_packet.h"
#include "clif.h"

/*
 * insert to head, so first one is last
 */
struct lldp_module *(*register_tlv_table[])(void) = {
	mand_register,
	basman_register,
	dcbx_register,
	med_register,
	ieee8023_register,
	evb_register,
	evb22_register,
	vdp_register,
	vdp22_register,
	ecp22_register,
	ieee8021qaz_register,
	NULL,
};

char *cfg_file_name = NULL;
bool daemonize = 0;
int loglvl = LOG_WARNING;
int omit_tstamp;

static const char *lldpad_version =
"lldpad v" VERSION_STR "\n"
"Copyright (c) 2007-2010, Intel Corporation\n"
"\nPortions used and/or modified from:  hostapd v 0.5.7\n"
"Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi> and contributors";

static void init_modules(void)
{
	struct lldp_module *module;
	struct lldp_module *premod = NULL;
	int i = 0;

	LIST_INIT(&lldp_head);
	for (i = 0; register_tlv_table[i]; i++) {
		module = register_tlv_table[i]();
		if (!module)
			continue;
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
	fprintf(stderr,
		"\n"
		"usage: lldpad [-hdksptv] [-f configfile] [-V level]"
		"\n"
		"options:\n"
		"   -h  show this usage\n"
		"   -d  run daemon in the background\n"
		"   -k  terminate current running lldpad\n"
		"   -s  remove lldpad state records\n"
		"   -p  Do not create PID file\n"
		"   -t  omit timestamps in log messages\n"
		"   -v  show version\n"
		"   -f  use configfile instead of default\n"
		"   -V  set syslog level\n");

	exit(1);
}

/*
 * send_event: Send message to attach clients.
 * @moduleid - module identification of sender or 0 for legacy format
 * @msg - string encoded message
 */
void send_event(int level, u32 moduleid, char *msg)
{
	struct clif_data *cd = NULL;

	cd = (struct clif_data *) eloop_get_user_data();
	if (cd)
		ctrl_iface_send(cd, level, moduleid, msg, strlen(msg));
}

static void remove_all_adapters(void)
{
	struct port *port, *next;

	for (port = porthead; port; port = next) {
		next = port->next;
		remove_port(port->ifname);
	}

	return;
}

void
lldpad_reconfig(UNUSED int sig, UNUSED void *eloop_ctx, UNUSED void *signal_ctx)
{
	LLDPAD_WARN("lldpad: SIGHUP received reinit...");
	/* Send LLDP SHUTDOWN frames and deinit modules */
	clean_lldp_agents();
	deinit_modules();
	remove_all_adapters();
	destroy_cfg();

	/* Reinit config file and modules */
	init_cfg();
	init_modules();
	init_ports();

	return;
}

struct {
	const char *path;
	int score;
} oom_adjust[] = {{"/proc/self/oom_score_adj", -1000},
		  {"/proc/self/oom_adj", -17},
		  {NULL, 0}};

/*
 * lldp_oom_adjust: Set oom score for lldpad
 *
 * Note we have two interfaces depending on kernel version.
 */
void lldpad_oom_adjust(void)
{
	int i;

	for (i = 0; oom_adjust[i].path; i++) {
		FILE *oom_file = fopen(oom_adjust[i].path, "r+");
		int err;

		if (!oom_file)
			continue;

		err = fprintf(oom_file, "%d", oom_adjust[i].score);
		fclose(oom_file);
		if (err < 0)
			continue;

		return;
	}

	LLDPAD_DBG("lldpad: OOM adjust failed\n");
};

int main(int argc, char *argv[])
{
	int c;
	struct clif_data *clifd;
	int fd = -1;
	char buf[32];
	int shm_remove = 0;
	int killme = 0;
	int print_v = 0;
	int pid_file = 1;
	pid_t pid;
	int cnt;
	int rc = 1;

	for (;;) {
		c = getopt(argc, argv, "hdksptvf:V:");
		if (c < 0)
			break;
		switch (c) {
		case 'f':
			if (cfg_file_name) {
				usage();
				break;
			}
			cfg_file_name = strdup(optarg);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'k':
			killme = 1;
			break;
		case 's':
			shm_remove = 1;
			break;
		case 'p':
			pid_file = 0;
			break;
		case 't':
			omit_tstamp = 1;
			break;
		case 'v':
			print_v = 1;
			break;
		case 'V':
			loglvl = atoi(optarg);
			if (loglvl > LOG_DEBUG)
				loglvl = LOG_DEBUG;
			if (loglvl < LOG_EMERG)
				loglvl = LOG_EMERG;
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}
	/* exit if invalid input in the command line */
	if (optind < argc )
		usage();

	if (print_v) {
		printf("%s\n", lldpad_version);
		exit(0);
	}

	if (cfg_file_name == NULL)
		cfg_file_name = DEFAULT_CFG_FILE;

	if (shm_remove) {
		mark_lldpad_shm_for_removal();
		exit(0);
	}

	if (killme) {
		pid = lldpad_shm_getpid();

		if (pid < 0) {
			perror("lldpad_shm_getpid failed");
			LLDPAD_WARN("lldpad_shm_getpid failed\n");
			exit (1);
		} else if (pid == PID_NOT_SET) {
			if (!lldpad_shm_setpid(DONT_KILL_PID)) {
				perror("lldpad_shm_setpid failed");
				LLDPAD_WARN("lldpad_shm_setpid failed\n");
				exit (1);
			} else {
				exit(0);
			}
		} else if (pid == DONT_KILL_PID) {
			exit (0);
		}

		if (!kill(pid, 0) && !kill(pid, SIGINT)) {
			cnt = 0;
			while (!kill(pid, 0) && cnt++ < 1000)
				usleep(10000);

			if (cnt >= 1000) {
				LLDPAD_WARN("failed to kill lldpad %d\n", pid);
				exit (1);
			}
		} else {
			perror("lldpad kill failed");
			LLDPAD_WARN("lldpad kill failed\n");
		}
		if (!lldpad_shm_setpid(DONT_KILL_PID)) {
			perror("lldpad_shm_setpid failed after kill");
			LLDPAD_WARN("lldpad_shm_setpid failed after kill");
			exit (1);
		}

		exit (0);
	}

	lldpad_oom_adjust();

	/* initialize lldpad user data */
	clifd = malloc(sizeof(struct clif_data));
	if (clifd == NULL) {
		LLDPAD_ERR("failed to malloc user data\n");
		exit(1);
	}

	/* initialize lldpad configuration file */
	if (!init_cfg()) {
		LLDPAD_ERR("failed to initialize configuration file\n");
		exit(1);
	}

	if (eloop_init(clifd)) {
		LLDPAD_ERR("failed to initialize event loop\n");
		exit(1);
	}

	/* initialize the client interface socket before daemonize */
	if (ctrl_iface_init(clifd) < 0) {
		LLDPAD_ERR("failed to register client interface\n");
		exit(1);
	}

	/* From this point on we know we're the only instance */
	if (daemonize && daemon(1, 0)) {
		LLDPAD_ERR("error daemonizing lldpad");
		exit(1);
	}

	if (pid_file) {
		fd = open(PID_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			LLDPAD_ERR("error opening lldpad pid file");
			exit(1);
		}

		if (lseek(fd, 0, SEEK_SET) < 0) {
			LLDPAD_ERR("error seeking lldpad pid file\n");
			goto out_fail;
		}

		memset(buf, 0, sizeof(buf));
		sprintf(buf, "%u\n", getpid());
		if (write(fd, buf, sizeof(buf)) < 0)
			perror("error writing to lldpad pid file");
		if (fsync(fd) < 0)
			perror("error syncing lldpad pid file");

		close(fd);
	}

	pid = lldpad_shm_getpid();
	if (pid < 0) {
		LLDPAD_ERR("error getting shm pid");
		goto out_fail;
	} else if (pid == PID_NOT_SET) {
		if (!lldpad_shm_setpid(getpid())) {
			perror("lldpad_shm_setpid failed");
			LLDPAD_ERR("lldpad_shm_setpid failed\n");
			goto out_fail;
		}
	} else if (pid != DONT_KILL_PID) {
		if (!kill(pid, 0)) {
			LLDPAD_ERR("lldpad already running");
			goto out_fail;
		}
		/* pid in shm no longer has a process, go ahead
                 * and let this lldpad instance execute.
		 */
		if (!lldpad_shm_setpid(getpid())) {
			perror("lldpad_shm_setpid failed");
			LLDPAD_ERR("error overwriting shm pid");
			goto out_fail;
		}
	}

	openlog("lldpad", LOG_CONS | LOG_PID, LOG_DAEMON);
	setlogmask(LOG_UPTO(loglvl));

	/* setup event netlink interface for user space processes.
	 * This needs to be setup first to ensure it gets lldpads
	 * pid as netlink address.
	 */
	if (event_iface_init_user_space() < 0) {
		LLDPAD_ERR("lldpad failed to start - "
			   "failed to register user space event interface\n");
		closelog();
		goto out_fail;
	}

	init_modules();

	eloop_register_signal_terminate(eloop_terminate, NULL);
	eloop_register_signal_reconfig(lldpad_reconfig, NULL);

	/* setup LLDP agent */
	if (!start_lldp_agents()) {
		LLDPAD_ERR("failed to initialize LLDP agent\n");
		goto out;
	}

	/* setup event RT netlink interface */
	if (event_iface_init() < 0) {
		LLDPAD_ERR("failed to register event interface\n");
		goto out;
	}

	/* Find available interfaces and add adapters */
	init_ports();

	if (ctrl_iface_register(clifd) < 0) {
		LLDPAD_ERR("lldpad failed to start - "
			   "failed to register control interface\n");
		goto out;
	}

	rc = 0;
	eloop_run();

	clean_lldp_agents();
	deinit_modules();
	remove_all_adapters();
	ctrl_iface_deinit(clifd);  /* free's clifd */
	event_iface_deinit();
	stop_lldp_agents();
out:
	eloop_destroy();
	if (!eloop_terminated())
		rc = 1;
	destroy_cfg();
	closelog();
out_fail:
	if (pid_file)
		unlink(PID_FILE);
	exit(rc);
}
