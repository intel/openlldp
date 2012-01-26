/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_
#include <syslog.h>
#include <stdbool.h>

extern bool daemonize;
extern int loglvl;

void log_message(int loglvl, const char *pFormat, ...)
	__attribute__((__format__(__printf__, 2, 3)));

#define LLDPAD_ERR(...) log_message(LOG_ERR,  __VA_ARGS__)
#define LLDPAD_WARN(...) log_message(LOG_WARNING, __VA_ARGS__)
#define LLDPAD_INFO(...) log_message(LOG_INFO, __VA_ARGS__)
#define LLDPAD_DBG(...) log_message(LOG_DEBUG, __VA_ARGS__)

#endif
