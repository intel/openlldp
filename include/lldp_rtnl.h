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

#ifndef _LLDP_RTNL_H
#define _LLDP_RTNL_H

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#include "include/linux/netlink.h"

/*
 * Helper functions to construct a netlink message.
 */
void mynla_nest_end(struct nlmsghdr *, struct nlattr *);
struct nlattr *mynla_nest_start(struct nlmsghdr *, int);
void mynla_put(struct nlmsghdr *, int, size_t, void *);
void mynla_put_u16(struct nlmsghdr *, int, __u16);
void mynla_put_u32(struct nlmsghdr *, int, __u32);

int get_operstate(char *ifname);
int set_operstate(char *ifname, __u8 operstate);
int set_linkmode(const char *ifname, __u8 linkmode);

#endif
