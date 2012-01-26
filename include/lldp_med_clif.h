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

#ifndef _LLDP_MED_CLIF_H
#define _LLDP_MED_CLIF_H

struct lldp_module *med_cli_register(void);
void med_cli_unregister(struct lldp_module *);
int med_print_tlv(u32, u16, char *);

#define ARG_MED_DEVTYPE    "devtype"
#define VAL_MED_NOT        "none"
#define VAL_MED_CLASS_I    "class1"
#define VAL_MED_CLASS_II   "class2"
#define VAL_MED_CLASS_III  "class3"
#define VAL_MED_NETCON     "netcon"

#endif
