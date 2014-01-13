/*******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2012

  Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>

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

*******************************************************************************/

#ifndef _LLDP_EVB22_H
#define _LLDP_EVB22_H

#include "lldp_mod.h"
#include "qbg22.h"

#define LLDP_MOD_EVB22_SUBTYPE	0xd
#define LLDP_MOD_EVB22_OUI	{ 0x00, 0x80, 0xc2, LLDP_MOD_EVB22_SUBTYPE }

enum {				/* EVB bit definitions defines */
	EVB_BGID = 0x4,		/* Bridge group ID */
	EVB_RRCAP = 0x2,	/* Bridge reflective relay capability */
	EVB_RRCTR = 0x1,	/* Bridge reflective relay control */
	EVB_SGID = 0x8,		/* Station group ID */
	EVB_RRREQ = 0x4,	/* Station reflective relay request */
	EVB_RRSTAT_YES = 0x1,	/* Station reflective relay status TRUE */
	EVB_RRSTAT_NO = 0x0,	/* Station reflective relay status NO */
	EVB_RRSTAT_DONT = 0x3,	/* Station reflective relay status unknown */
	EVB_ROL = 0x20,		/* Remote or local indicator */
	EVB_BRIDGE = 0x1,	/* EVB Bridge */
	EVB_STATION = 0x2	/* EVB Station */
};

/*
 * Function to set and extract maximum retries
 */
static inline u8 evb_maskoff_retries(u8 value)
{
	return value & 0x1f;
}

static inline u8 evb_set_retries(u8 value)
{
	return (value & 7) << 5;
}

static inline u8 evb_ex_retries(u8 value)
{
	return (value >> 5) & 7;
}

/*
 * Function to set and extract retransmission exponent.
 */
static inline u8 evb_maskoff_rte(u8 value)
{
	return value & 0xe0;
}

static inline u8 evb_set_rte(u8 value)
{
	return value & 0x1f;
}

static inline u8 evb_ex_rte(u8 value)
{
	return value & 0x1f;
}

/*
 * Function to set and extract evb mode.
 */
static inline u8 evb_maskoff_evbmode(u8 value)
{
	return value & 0x3f;
}

static inline u8 evb_set_evbmode(u8 value)
{
	return (value & 3) << 6;
}

static inline u8 evb_ex_evbmode(u8 value)
{
	return (value >> 6) & 3;
}

/*
 * Function to set and extract remote/local flag.
 */
static inline u8 evb_set_rol(u8 value)
{
	return (value & 1) << 5;
}

static inline u8 evb_ex_rol(u8 value)
{
	return (value >> 5) & 1;
}

/*
 * Function to set and extract resource wait delay.
 */
static inline u8 evb_maskoff_rwd(u8 value)
{
	return value & 0xe0;
}

static inline u8 evb_set_rwd(u8 value)
{
	return value & 0x1f;
}

static inline u8 evb_ex_rwd(u8 value)
{
	return value & 0x1f;
}

/*
 * Function to set and extract reinit keep alive.
 */
static inline u8 evb_maskoff_rka(u8 value)
{
	return value & 0xe0;
}

static inline u8 evb_set_rka(int value)
{
	return value & 0x1f;
}

static inline u8 evb_ex_rka(u8 value)
{
	return value & 0x1f;
}

/*
 * Function to set and extract reflective relay status.
 */
static inline u8 evb_maskoff_rrstat(u8 value)
{
	return value & 0xfc;
}

static inline u8 evb_set_rrstat(int value)
{
	return value & 3;
}

static inline u8 evb_ex_rrstat(u8 value)
{
	return value & 3;
}

/*
 * Function to set and extract reflective relay request.
 */
static inline u8 evb_maskoff_rrreq(int value)
{
	return value & 0xfb;
}

static inline u8 evb_set_rrreq(int value)
{
	return (value & 1) << 2;
}

static inline u8 evb_ex_rrreq(u8 value)
{
	return (value >> 2) & 1;
}

/*
 * Function to set and extract station group id.
 */
static inline u8 evb_maskoff_sgid(int value)
{
	return value & 0xf7;
}

static inline u8 evb_set_sgid(int value)
{
	return (value & 1) << 3;
}

static inline u8 evb_ex_sgid(u8 value)
{
	return (value >> 3) & 1;
}

/*
 * Function to set and extract bridge reflective relay capability.
 */
static inline u8 evb_maskoff_rrcap(int value)
{
	return value & 0xfd;
}

static inline u8 evb_set_rrcap(int value)
{
	return (value & 1) << 1;
}

static inline u8 evb_ex_rrcap(u8 value)
{
	return (value >> 1) & 1;
}

/*
 * Function to set and extract reflective relay control.
 */
static inline u8 evb_set_rrctr(int value)
{
	return value & 1;
}

static inline u8 evb_ex_rrctr(u8 value)
{
	return value & 1;
}

/*
 * Function to set and extract bridge group id.
 */
static inline u8 evb_maskoff_bgid(int value)
{
	return value & 0xfb;
}

static inline u8 evb_set_bgid(int value)
{
	return (value & 1) << 2;
}

static inline u8 evb_ex_bgid(u8 value)
{
	return (value >> 2) & 1;
}

struct evb22_tlv {	/* EVB TLV definition */
	u8 oui[3];
	u8 sub;
	u8 bridge_s;	/* Bridge status */
	u8 station_s;	/* Station status */
	u8 r_rte;	/* Retries and retransmssion exponent */
	u8 evb_mode;	/* Evb-mode, remove/local and resource wait delay */
	u8 rl_rka;	/* Remote/local and reinit keep alive */
} __attribute__ ((__packed__));

struct evb22_data {
	char ifname[IFNAMSIZ];
	enum agent_type agenttype;
	bool txmit;			/* True when EVB transmits enabled */
	bool vdp_start;			/* True when VDP module started */
	struct evb22_tlv out;		/* Currently supported */
	struct evb22_tlv last;		/* Last received */
	struct evb22_tlv policy;	/* Local policy */
	LIST_ENTRY(evb22_data) entry;
};

struct evb22_user_data {
	LIST_HEAD(evb22_head, evb22_data) head;
};

/*
 * Function Prototypes
 */
struct lldp_module *evb22_register(void);
void evb22_unregister(struct lldp_module *);
struct evb22_data *evb22_data(char *, enum agent_type);
struct arg_handlers *evb22_get_arg_handlers(void);
int evb22_conf_enabletx(char *, enum agent_type);
int evb22_conf_evbmode(char *, enum agent_type);
int evb22_conf_rrreq(char *, enum agent_type);
int evb22_conf_rrcap(char *, enum agent_type);
int evb22_conf_retries(char *, enum agent_type);
int evb22_conf_rwd(char *, enum agent_type);
int evb22_conf_rte(char *, enum agent_type);
int evb22_conf_rka(char *, enum agent_type);
int evb22_conf_retries(char *, enum agent_type);
int evb22_conf_gid(char *, enum agent_type);
#endif
