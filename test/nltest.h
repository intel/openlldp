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
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#ifndef _NLUTIL_H
#define _NLUTIL_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <asm/errno.h>
#include <sys/socket.h>
#include "linux/if.h"
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "linux/dcbnl.h"

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define BCN_ADDR_OPTION_LEN       8         /* 8 hex digits */
#define ETH_ALEN      6

enum dcb_pfc_type {
	pfc_disabled = 0,
	pfc_enabled_tx,
	pfc_enabled_rx,
	pfc_enabled_full
};

enum strict_prio_type {
	prio_none = 0,
	prio_group,
	prio_link
};

struct tc_config {
	__u8 bwg_id;
	__u8 up_to_tc_bitmap;
	__u8 prio_type;
	__u8 bwg_percent;
};

typedef struct bcn_cfg {
	__u8 bcna[8];/* CM-Tag BCNA field */
	struct {
		char cp_admin;     /* CP admin mode */
		char rp_admin;     /* RP admin mode */
		char rp_oper;      /* RP Operational mode */
		char rem_tag_oper; /* Remove CM tag Operational mode */
	}up_settings[8]; /* Index is user priority */
	float rp_alpha; /* RP max decrease factor */
	float rp_beta;  /* RP max increase factor */
	float rp_gd;    /* RP decrement coefficient */
	float rp_gi;    /* RP increment coefficient */
	int rp_tmax;     /* RP max time to backoff after BCN0 */
	int cp_sf;       /* CP sampling interval fixed - Not used by driver */
	int rp_c;        /* RP link capacity */
	int rp_ri;       /* RP initial rate */
	__u16 rp_td;       /* RP drift interval */
	__u16 rp_rmin;     /* RP default rate after 1st BCN0 */
	__u8 rp_w;         /* RP derivate rate */
	__u8 rp_rd;        /* RP drift factor */
	__u8 rp_ru;        /* RP rate unit */
	__u8 rp_wrtt;      /* RP RTT moving average weight */ 
} bcn_cfg;

typedef struct appgroup_attribs {
	__u8  dcb_app_idtype;
	__u16 dcb_app_id;
	__u8  dcb_app_priority;
} appgroup_attribs;

#define NLA_HDRLEN           ((int) NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_DATA(nla)        ((void *)((char*)(nla) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)     (len - NLA_HDRLEN)

int nl_sd;
int dbg = 1;
 
/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE    1024

extern unsigned if_nametoindex(const char *ifname);


#endif  /* _NLUTIL_H */
