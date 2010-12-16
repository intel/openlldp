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

#ifndef _LLDP_MAND_H
#define _LLDP_MAND_H

#include "lldp_mod.h"

#define LLDP_MOD_MAND	1

struct mand_data {
	char ifname[IFNAMSIZ];
	struct unpacked_tlv *chassis;
	struct unpacked_tlv *portid;
	struct unpacked_tlv *ttl;
	struct unpacked_tlv *end;
	u8 rebuild_chassis:1;
	u8 rebuild_portid:1;
	LIST_ENTRY(mand_data) entry;
};

struct mand_user_data {
	LIST_HEAD(mand_head, mand_data) head;
};

struct lldp_module *mand_register(void);
void mand_unregister(struct lldp_module *mod);
struct packed_tlv *mand_gettlv(struct port *port);
void mand_ifdown(char *);
void mand_ifup(char *);
int mand_clif_cmd(void *, struct sockaddr_un *,
		  socklen_t , char *, int, char *);

#endif /* _LLDP_MAND_H */
