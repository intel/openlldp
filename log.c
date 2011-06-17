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
#include "dcb_protocol.h"
#include "messages.h"
#include "lldpad.h"


void log_message(u32 msgid,  const char *format,  ...)
{
	int a, b;
	char fmt[256];

	va_list va, vb;
	va_start(va, format);
	va_copy(vb, va);

	if (!daemonize && loglvl >= msgid) {
		vprintf(format, vb);
		va_end(va);
		return;
	} else if (!daemonize) {
		va_end(va);
		return;
	}

	switch(msgid) {
	case MSG_INFO_DEBUG_STRING:
		vsyslog(LOG_DEBUG, format, vb);
		break;
	case MSG_ERR_SERVICE_START_FAILURE:
		snprintf(fmt, sizeof(fmt), "lldpad failed to start - %s", format);
		syslog(LOG_ERR, fmt, va_arg(va, char *));
		break;
	case MSG_ERR_RESOURCE_MEMORY:
		break;
	case MSG_ERR_ADD_CARD_FAILURE:
		syslog(LOG_ERR,
			"failed to add interface %s",
			va_arg(va, char *));
		break;
	case MSG_ERR_DCB_INVALID_TX_TOTAL_BWG:
		syslog(LOG_ERR,
			"invalid total priority group bandwidth for tx [%d%%]",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_RX_TOTAL_BWG:
		syslog(LOG_ERR,
			"invalid total priority group bandwidth for rx [%d%%]",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_TX_BWG_IDX:
		syslog(LOG_ERR,
			"invalid transmit priority group index [%d]",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_RX_BWG_IDX:
		syslog(LOG_ERR,
			"invalid receive priority group index [%d]",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_TX_LSP_NZERO_BW_TC:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"transmit link strict user priority[%d] has non-zero "
			"bandwidth [%d%%]", a, b);
		break;
	case MSG_ERR_DCB_INVALID_RX_LSP_NZERO_BW_TC:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"receive link strict user priority[%d] has non-zero "
			"bandwidth [%d%%]", a, b);
		break;
	case MSG_ERR_DCB_TOO_MANY_LSP_PGIDS:
		syslog(LOG_ERR,
			"only one link strict priority group is allowed [%d%%]",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_TX_ZERO_BW_TC:
		syslog(LOG_ERR,
			"transmit user priority[%d] has zero bandwidth",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_RX_ZERO_BW_TC:
		syslog(LOG_ERR,
			"receive user priority[%d] has zero bandwidth",
			va_arg(va, int));
		break;
	case MSG_ERR_DCB_INVALID_TX_LSP_NZERO_BWG:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"transmit link strict priority group [%d] has a "
			"non-zero bandwidth [%d%%]", a, b);
		break;
	case MSG_ERR_DCB_INVALID_RX_LSP_NZERO_BWG:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"receive link strict priority group [%d] has a "
			"non-zero bandwidth [%d%%]", a, b);
		break;
	case MSG_ERR_DCB_INVALID_TX_BWG:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"transmit priority group [%d] has invalid total "
			"bandwidth [%d%%], should be 0 or 100", a, b);
		break;
	case MSG_ERR_DCB_INVALID_RX_BWG:
		a = va_arg(va, int);
		b = va_arg(va, int);
		syslog(LOG_ERR,
			"receive priority group [%d] has invalid total "
			"bandwidth [%d%%], should be 0 or 100", a, b);
		break;
	case MSG_ERR_TX_SM_INVALID:
		syslog(LOG_ERR,
			"LLDP transmit state machine encountered an invalid "
			"state.");
		break;
	case MSG_ERR_RX_SM_INVALID:
		syslog(LOG_ERR,
			"LLDP receive state machine encountered an invalid "
			"state.");
		break;
	case MSG_ERR_DCB_INVALID_CONFIG_FILE:
		syslog(LOG_ERR,
			"lldpad failed to read config file - %s",
			va_arg(va, char *));
		break;
	case MSG_INFO_LLINK_DISABLED:
		syslog(LOG_INFO,
			"FCoE logical link on %s is disabled",
			va_arg(va, char *));
		break;
	case MSG_INFO_LLINK_ENABLED:
		syslog(LOG_INFO,
			"FCoE logical link on %s is enabled",
			va_arg(va, char *));
		break;
	case MSG_INFO_LLINK_OPER:
		syslog(LOG_INFO,
			"FCoE logical link on %s is operational",
			va_arg(va, char *));
		break;
	case MSG_ERR_LLINK_NONOPER:
		syslog(LOG_ERR,
			"FCoE logical link on %s is not operational",
			va_arg(va, char *));
		break;
	default:
		vsyslog(msgid, format, vb);
		break;
	}

	va_end(va);
}
