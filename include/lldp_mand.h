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

#ifndef _LLDP_MAND_H
#define _LLDP_MAND_H

#include "lldp_mod.h"
#include "lldp_mand_cmds.h"

#define LLDP_MOD_MAND	1

struct tlv_info_chassis {
	u8 sub;
	union {
		u8 ccomp[255];
		u8 ifalias[255];
		u8 pcomp[255];
		u8 mac[6];
		struct  {
			u8 type;
			union {
				struct in_addr v4;
				struct in6_addr v6;
			} __attribute__ ((__packed__)) ip;
		} __attribute__ ((__packed__)) na;
		u8 ifname[255];
		u8 local[255];
	} __attribute__ ((__packed__)) id;
} __attribute__ ((__packed__));

struct tlv_info_portid {
	u8 sub;
	union {
		u8 ifalias[255];
		u8 pcomp[255];
		u8 mac[6];
		struct  {
			u8 type;
			union {
				struct in_addr v4;
				struct in6_addr v6;
			} __attribute__ ((__packed__)) ip;
		} __attribute__ ((__packed__)) na;
		u8 ifname[255];
		u8 circuit[255];
		u8 local[255];
	} __attribute__ ((__packed__)) id;
} __attribute__ ((__packed__));

struct mand_data {
	char ifname[IFNAMSIZ];
	enum agent_type agenttype;
	struct unpacked_tlv *chassis;
	struct unpacked_tlv *portid;
	struct unpacked_tlv *ttl;
	struct unpacked_tlv *end;
	u8 rebuild_chassis:1;
	u8 rebuild_portid:1;
	bool read_shm;
	LIST_ENTRY(mand_data) entry;
};

struct mand_user_data {
	LIST_HEAD(mand_head, mand_data) head;
};

struct mand_data *mand_data(const char *, enum agent_type);
struct lldp_module *mand_register(void);
void mand_unregister(struct lldp_module *mod);
struct packed_tlv *mand_gettlv(struct port *, struct lldp_agent *);
void mand_ifdown(char *, struct lldp_agent *);
void mand_ifup(char *, struct lldp_agent *);
#endif /* _LLDP_MAND_H */
