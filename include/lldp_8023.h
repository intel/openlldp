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

#ifndef _LLDP_8023_H
#define _LLDP_8023_H

#include "lldp_mod.h"
#include "lldp_tlv.h"

#define LLDP_MOD_8023	OUI_IEEE_8023

struct ieee8023_data {
	char ifname[IFNAMSIZ];
	struct unpacked_tlv *maccfg;
	struct unpacked_tlv *powvmdi;
	struct unpacked_tlv *linkagg;
	struct unpacked_tlv *maxfs;
	LIST_ENTRY(ieee8023_data) entry;
};

struct ieee8023_user_data {
	LIST_HEAD(ieee8023_head, ieee8023_data) head;
};

struct lldp_module *ieee8023_register(void);
void ieee8023_unregister(struct lldp_module *mod);
struct packed_tlv *ieee8023_gettlv(struct port *port);
void ieee8023_ifdown(char *);
void ieee8023_ifup(char *);

#endif /* _LLDP_8023_H */
