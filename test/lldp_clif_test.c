/*******************************************************************************
  SPDX-Identifier: GPL-2.0-or-later

  LLDP Agent Daemon (LLDPAD) Software - clif unit tests
  Copyright (C) 2018, Red Hat, Inc.

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

#include "lldp.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* functions to test */
extern void print_mng_addr(u16 len, char *info);

/* tests for output functions */
static int hook_fd = -1;
static FILE *stdout_hook;
static char *test_name;

static void hook_stdout(char *test_id)
{
	if (!test_id)
		test_name = "test_tmp.txt";

	if (hook_fd == -1) {
		hook_fd = dup(STDOUT_FILENO);
		stdout_hook = freopen(test_id, "w", stdout);
		test_name = strdup(test_id);

		if (!stdout_hook || !test_name) {
			fprintf(stderr, "Fatal error: unable to hook stdout\n");
			exit(1);
		}
	}
}

static void unhook_stdout()
{
	if (hook_fd != -1) {
		dup2(hook_fd, STDOUT_FILENO);
		stdout = fdopen(STDOUT_FILENO, "w");
		close(hook_fd);
		hook_fd = -1;

		unlink(test_name);
		free(test_name);
		test_name = NULL;
	}
}

static int test_mgmt_printing()
{
	char *mgmt_info_test;
	int result = 1;
	FILE *output;
	int ctr = 0;

	mgmt_info_test =
		"05010a2ff8f9" /* addrlen + subtype + addr */
		"0100000000" /* if-subtype + ifnum */
		"0c0103060102011f0101010100"; /* oid-len + oid */

	/* start by hooking the stdout filedescriptor */
	hook_stdout("test_mgmt_printing.txt");

	print_mng_addr(strlen(mgmt_info_test), mgmt_info_test);

	fflush(stdout);

	output = fopen("test_mgmt_printing.txt", "r");
	if (!output)
		goto done;

	while (!feof(output) && ctr != 3) {
		char buf[1024];
		if (!fgets(buf, sizeof(buf), output))
			goto done;

		if (!strcmp(buf, "IPv4: 10.47.248.249\n"))
			ctr++;
		else if (!strcmp(buf, "\tUnknown interface subtype: 0\n"))
			ctr++;
		else if (!strcmp(buf, "\tOID: 0.1.3.6.1.2.1.31.1.1.1.1.0\n"))
			ctr++;
		else {
			fprintf(stderr, "FATAL: unknown line '%s'\n", buf);
			goto done;
		}
	}
	result = 0;

done:
	if (output)
		fclose(output);

	unhook_stdout();
	return result;
}

int main(void)
{
	int error_counter = 0;

	error_counter += test_mgmt_printing();

	return error_counter ? -1 : 0;
}

/* Local Variables:    */
/* c-indent-level: 8   */
/* c-basic-offset: 8   */
/* tab-width: 8        */
/* indent-tabs-mode: t */
/* End:                */
