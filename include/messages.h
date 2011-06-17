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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_
#include <syslog.h>
#include <stdbool.h>

#define MSG_INFO_DEBUG_STRING 1

#define MSG_ERR_SERVICE_START_FAILURE 14
#define MSG_ERR_RESOURCE_MEMORY 15
#define MSG_ERR_ADD_CARD_FAILURE 16
#define MSG_ERR_DCB_INVALID_TX_TOTAL_BWG 17
#define MSG_ERR_DCB_INVALID_RX_TOTAL_BWG 18
#define MSG_ERR_DCB_INVALID_TX_BWG_IDX 19
#define MSG_ERR_DCB_INVALID_RX_BWG_IDX 20
#define MSG_ERR_DCB_INVALID_TX_LSP_NZERO_BW_TC 21
#define MSG_ERR_DCB_INVALID_RX_LSP_NZERO_BW_TC 22
#define MSG_ERR_DCB_TOO_MANY_LSP_PGIDS 23
#define MSG_ERR_DCB_INVALID_TX_ZERO_BW_TC 24
#define MSG_ERR_DCB_INVALID_RX_ZERO_BW_TC 25
#define MSG_ERR_DCB_INVALID_TX_LSP_NZERO_BWG 26
#define MSG_ERR_DCB_INVALID_RX_LSP_NZERO_BWG 27
#define MSG_ERR_DCB_INVALID_TX_BWG 28
#define MSG_ERR_DCB_INVALID_RX_BWG 29
#define MSG_ERR_TX_SM_INVALID 30
#define MSG_ERR_RX_SM_INVALID 31
#define MSG_ERR_DCB_INVALID_CONFIG_FILE 32

#define MSG_INFO_LLINK_DISABLED 37
#define MSG_INFO_LLINK_ENABLED 38
#define MSG_INFO_LLINK_OPER 39
#define MSG_ERR_LLINK_NONOPER 40

extern bool daemonize;
extern int loglvl;

void log_message(__u32 dwMsgId, const char *pFormat, ...);

#define LLDPAD_ERR(...) log_message(LOG_ERR,  __VA_ARGS__)
#define LLDPAD_WARN(...) log_message(LOG_WARNING, __VA_ARGS__)
#define LLDPAD_INFO(...) log_message(LOG_INFO, __VA_ARGS__)
#define LLDPAD_DBG(...) log_message(LOG_DEBUG, __VA_ARGS__)

#endif
