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
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "messages.h"

/*
 * Prepend each entry with a time stamp.
 */
static void showtime(void)
{
	struct timeval tv;
	struct tm now;

	if (!gettimeofday(&tv, NULL)) {
		localtime_r(&tv.tv_sec, &now);
		printf("%02d:%02d:%02d.%06ld ",
			now.tm_hour, now.tm_min, now.tm_sec, tv.tv_usec);
	}
}

/* Helper macros for handling struct os_time */
void log_message(int level, const char *format, ...)
{
	static int bypass_time;
	va_list va, vb;
	va_start(va, format);
	va_copy(vb, va);

	if (daemonize)
		vsyslog(level, format, vb);
	else if (loglvl >= level) {
		if (!bypass_time)
			showtime();
		vprintf(format, vb);
		bypass_time = strchr(format, '\n') == 0;
	}
	va_end(va);
}
