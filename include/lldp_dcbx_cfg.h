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

#ifndef _LLDP_DCBX_CFG_H_
#define _LLDP_DCBX_CFG_H_

#define DCBX_SETTING "dcbx"

/* Enumerations used to set 'dcb_enable' configuration values.
 * The DCBX default case is to enable DCBX and configure hardware
 * when receiving a DCBX TLV from the peer. DISABLED and ENABLED
 * bits are provided to force a preferred strategy.
 */
enum {
	LLDP_DCBX_DISABLED	= 0,
	LLDP_DCBX_ENABLED	= 1,
	LLDP_DCBX_DEFAULT	= 2
};

int dcbx_default_cfg_file(void);
int get_dcb_enable_state(char *device_name, int *result);
int save_dcb_enable_state(char *device_name, int dcb_enable);
int get_dcbx_version(int *result);
int save_dcbx_version(int dcbx_version);

#endif // _LLDP_DCBX_CFG_H_
