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

#ifndef _LLDP_BASMAN_H
#define _LLDP_BASMAN_H

#include "lldp.h"
#include "lldp_mod.h"
#include "lldp_tlv.h"

#define LLDP_MOD_BASIC	2

struct basman_data {
	char ifname[IFNAMSIZ];
	enum agent_type agenttype;
	struct unpacked_tlv *portdesc;
	struct unpacked_tlv *sysname;
	struct unpacked_tlv *sysdesc;
	struct unpacked_tlv *syscaps;
	struct unpacked_tlv *manaddr[MANADDR_MAX];
	int macnt;
	LIST_ENTRY(basman_data) entry;
};

struct basman_user_data {
	LIST_HEAD(basman_head, basman_data) head;
};

struct lldp_module *basman_register(void);
void basman_unregister(struct lldp_module *mod);
struct packed_tlv *basman_gettlv(struct port *, struct lldp_agent *);
void basman_ifdown(char *, struct lldp_agent *);
void basman_ifup(char *, struct lldp_agent *);

#endif /* _LLDP_BASMAN_H */
