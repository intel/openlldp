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

#ifndef _LLDP_8023_H
#define _LLDP_8023_H

#include "lldp_mod.h"
#include "lldp_tlv.h"

#define LLDP_MOD_8023	OUI_IEEE_8023

struct ieee8023_data {
	char ifname[IFNAMSIZ];
	enum agent_type agenttype;
	struct unpacked_tlv *maccfg;
	struct unpacked_tlv *powvmdi;
	struct unpacked_tlv *linkagg;
	struct unpacked_tlv *maxfs;
	struct unpacked_tlv *add_eth_caps;
	bool enabled_preemption;
	LIST_ENTRY(ieee8023_data) entry;
};

struct ieee8023_user_data {
	LIST_HEAD(ieee8023_head, ieee8023_data) head;
};

struct lldp_module *ieee8023_register(void);
void ieee8023_unregister(struct lldp_module *mod);
struct packed_tlv *ieee8023_gettlv(struct port *, struct lldp_agent *);
void ieee8023_ifdown(char *, struct lldp_agent *);
void ieee8023_ifup(char *, struct lldp_agent *);
int ieee8023_rchange(struct port *port, struct lldp_agent *agent,
		     struct unpacked_tlv *tlv);

#endif /* _LLDP_8023_H */
