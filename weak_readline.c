/*
 * LLDP Agent Daemon (LLDPAD) Software
 * Copyright(c) 2012 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * open-lldp Mailing List <lldp-devel@open-lldp.org>
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <dlfcn.h>

static int inited;

static char *(*readline_p)(const char *);
static void (*using_history_p)(void);
static void (*stifle_history_p)(int);
static void (*add_history_p)(const char *);

static void weak_readline_init(void)
{
	void *hist_handle;
	void *rl_handle;

	inited = 1;
	hist_handle = dlopen("libhistory.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!hist_handle)
		return;
	rl_handle = dlopen("libreadline.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!rl_handle)
		goto out;

	using_history_p = dlsym(hist_handle, "using_history");
	stifle_history_p = dlsym(hist_handle, "stifle_history");
	add_history_p = dlsym(hist_handle, "add_history");
	readline_p = dlsym(rl_handle, "readline");

	if (readline_p && using_history_p && stifle_history_p && add_history_p)
		return;

	dlclose(rl_handle);
	rl_handle = NULL;
out:
	dlclose(hist_handle);
	hist_handle = NULL;
	readline_p = NULL;
	using_history_p = NULL;
	stifle_history_p = NULL;
	add_history_p = NULL;
}

void using_history(void)
{
	if (!inited)
		weak_readline_init();

	if (using_history_p)
		using_history_p();
}

void stifle_history(int max)
{
	if (!inited)
		weak_readline_init();

	if (stifle_history_p)
		stifle_history_p(max);
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

char *readline(const char *prompt)
{
	if (!inited)
		weak_readline_init();

	if (readline_p)
		return readline_p(prompt);

	return do_readline(prompt);
}

void add_history(const char *cmd)
{
	if (!inited)
		weak_readline_init();

	if (add_history_p)
		add_history_p(cmd);
}
