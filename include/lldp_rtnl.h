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
void mynla_put_u8(struct nlmsghdr *, int, __u8);
void mynla_put_u16(struct nlmsghdr *, int, __u16);
void mynla_put_u32(struct nlmsghdr *, int, __u32);
void mynla_put_s32(struct nlmsghdr *nlh, int type, __s32);
__u8 mynla_get_u8(const struct nlattr *);
__u16 mynla_get_u16(const struct nlattr *);
__u32 mynla_get_u32(const struct nlattr *);
__s32 mynla_get_s32(const struct nlattr *);
void mynla_get(const struct nlattr *, size_t, void *);
void *mynla_data(const struct nlattr *);
int mynla_payload(const struct nlattr *);
int mynla_type(const struct nlattr *);
int mynla_ok(const struct nlattr *, int);
int mynla_total_size(int);
struct nlattr *mynla_next(const struct nlattr *, int *);
int mynla_parse(struct nlattr **, size_t, struct nlattr *, int);

int get_operstate(char *ifname);
int set_operstate(char *ifname, __u8 operstate);
int set_linkmode(int ifindex, const char *ifname, __u8 linkmode);

#endif
