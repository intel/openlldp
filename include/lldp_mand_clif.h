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
  e1000-eedc Mailing List <e1000-eedc@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _LLDP_MAND_CLIF_H
#define _LLDP_MAND_CLIF_H

#include "lldp.h"

struct lldp_module *mand_cli_register(void);
void mand_cli_unregister(struct lldp_module *);
int mand_print_tlv(u32, u16, char *);

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
	cmd_if,
	cmd_nop,
} lldp_cmd;

typedef enum {
	op_enable    = 0x0001,
	op_disable   = 0x0002,
	op_add       = 0x0004,
	op_remove    = 0x0008,
	op_rx_enable = 0x0010,
	op_tx_enable = 0x0020,
	op_local     = 0x0040,
	op_neighbor  = 0x0080,
	op_arg       = 0x0100,
} lldp_op;

struct tlv {
	u32 tlvid;
	char *infostr;
};

#define TLVID_PREFIX    "tlvid"
#define ARG_ADMINSTATUS "adminStatus"
#define VAL_RXTX        "rxtx"
#define VAL_RX          "rx"
#define VAL_TX          "tx"
#define VAL_DISABLED    "disabled"
#define VAL_INVALID     "invalid"

#define ARG_TLVTXENABLE "enableTx"
#define ARG_TLVINFO	"info"
#define VAL_YES         "yes"
#define VAL_NO          "no"


#endif
