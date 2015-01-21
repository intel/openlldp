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

#ifndef LLDPAD_STATUS_H
#define LLDPAD_STATUS_H

typedef enum {
	cmd_success = 0,
	cmd_failed,
	cmd_device_not_found,
	cmd_agent_not_found,
	cmd_invalid,
	cmd_bad_params,
	cmd_peer_not_present,
	cmd_ctrl_vers_not_compatible,
	cmd_not_capable,
	cmd_not_applicable,
	cmd_no_access,
	cmd_agent_not_supported,
	cmd_max_status,
} cmd_status;

#endif /* LLDPAD_STATUS_H */
