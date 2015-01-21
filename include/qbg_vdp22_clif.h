/*******************************************************************************

  Implementation of VDP 22 (ratified standard) according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2014

  Author(s): Thomas Richter <tmricht@linux.vnet.ibm.com>

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

/*
 * Client command interface for vdp22 module.
 */

#ifndef QBG_VDP22_CLIF_H
#define QBG_VDP22_CLIF_H
typedef enum {
	cmd_getstats,
	cmd_gettlv,
	cmd_settlv,
	cmd_get_lldp,
	cmd_set_lldp,
	cmd_quit,
	cmd_license,
	cmd_version,
	cmd_help,
	cmd_ping,
	cmd_nop
} vdp22_cmd;

typedef enum {
	op_local = 0x1,
	op_neighbor = 0x2,
	op_arg = 0x4,
	op_argval = 0x8,
	op_config = 0x10,
	op_delete = 0x20,
	op_key = 0x40
} vdp22_op;

struct lldp_module *vdp22_cli_register(void);
#endif
