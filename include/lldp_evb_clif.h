/*******************************************************************************

  implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>

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

*******************************************************************************/

#ifndef _LLDP_EVB_CLIF_H
#define _LLDP_EVB_CLIF_H

struct lldp_module *evb_cli_register(void);
void evb_cli_unregister(struct lldp_module *);
int evb_print_tlv(u32, u16, char *);

#define EVB_BUF_SIZE			256

#define ARG_EVB_FORWARDING_MODE		"fmode"

#define VAL_EVB_FMODE_BRIDGE		"bridge"
#define VAL_EVB_FMODE_REFLECTIVE_RELAY	"reflectiverelay"

#define ARG_EVB_CAPABILITIES		"capabilities"

#define VAL_EVB_CAPA_RTE		"rte"
#define VAL_EVB_CAPA_ECP		"ecp"
#define VAL_EVB_CAPA_VDP		"vdp"
#define VAL_EVB_CAPA_NONE		"none"

#define ARG_EVB_VSIS			"vsis"

#define ARG_EVB_RTE			"rte"

#endif
