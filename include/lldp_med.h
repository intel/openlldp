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

#ifndef _LLDP_MED_H
#define _LLDP_MED_H

#include "lldp.h"
#include "lldp_mod.h"
#include "lldp_tlv.h"

#define LLDP_MOD_MED	OUI_TIA_TR41

struct med_data {
	char ifname[IFNAMSIZ];
	enum agent_type agenttype;
	struct unpacked_tlv *medcaps;
	struct unpacked_tlv *netpoli;
	struct unpacked_tlv *locid;
	struct unpacked_tlv *extpvm;
	struct unpacked_tlv *inv_hwrev;
	struct unpacked_tlv *inv_fwrev;
	struct unpacked_tlv *inv_swrev;
	struct unpacked_tlv *inv_serial;
	struct unpacked_tlv *inv_manufacturer;
	struct unpacked_tlv *inv_modelname;
	struct unpacked_tlv *inv_assetid;
	LIST_ENTRY(med_data) entry;
};

struct med_user_data {
	LIST_HEAD(med_head, med_data) head;
};

struct lldp_module *med_register(void);
void med_unregister(struct lldp_module *mod);
struct packed_tlv *med_gettlv(struct port *, struct lldp_agent *);
void med_ifdown(char *, struct lldp_agent *);
void med_ifup(char *, struct lldp_agent *);

#endif /* _LLDP_MED_H */
