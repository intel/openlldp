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

#ifndef AGENT_H
#define AGENT_H

#include "lldp.h"
#include "mibdata.h"

#ifndef ETH_ALEN
#define ETH_ALEN    6
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ    16  /* must match MAX_DEVICE_NAME_LEN */
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL   0x0003
#endif

enum agent_type {
	NEAREST_BRIDGE = 0,
	NEAREST_NONTPMR_BRIDGE,
	NEAREST_CUSTOMER_BRIDGE,
	AGENT_MAX,
};

/* IEEE 802.1AB-2009 - Table 7-1: group MAC addresses used by LLDP */
static const u8 nearest_bridge[ETH_ALEN] = {0x01,0x80,0xc2,0x00,0x00,0x0e};
static const u8 nearest_nontpmr_bridge[ETH_ALEN] = {0x01,0x80,0xc2,0x00,0x00,0x03};
static const u8 nearest_customer_bridge[ETH_ALEN] = {0x01,0x80,0xc2,0x00,0x00,0x00};

struct agenttimers {
/* Tx */
	u16 state;
	u16 reinitDelay;
	u16 msgTxHold;
	u16 msgTxInterval;
	u16 msgFastTx;
	u16 txFastInit;
	u16 txTTR;
	u16 txShutdownWhile;
	u16 txCredit;
	u16 txMaxCredit;
	bool txTick;
/* Rx */
	u16 tooManyNghbrsTimer;
	u16 rxTTL;
	u16 lastrxTTL;  /* cache last received */
};

struct agenttx {
	u8 *frameout;
	u32 sizeout;
	u8 state;
	u8 localChange;
	u16 txTTL;
	bool txNow;
	u16 txFast;
};

/* per agent statistical counter as in chapter 9.2.6
 * of IEEE 802.1AB-2009 */
struct agentstats {
/* Tx */
	u32 statsFramesOutTotal;
/* Rx */
	u32 statsAgeoutsTotal;
	u32 statsFramesDiscardedTotal;
	u32 statsFramesInErrorsTotal;
	u32 statsFramesInTotal;
	u32 statsTLVsDiscardedTotal;
	u32 statsTLVsUnrecognizedTotal;
};

typedef struct rxmanifest{
	struct unpacked_tlv *chassis;
	struct unpacked_tlv *portid;
	struct unpacked_tlv *ttl;
	struct unpacked_tlv *portdesc;
	struct unpacked_tlv *sysname;
	struct unpacked_tlv *sysdesc;
	struct unpacked_tlv *syscap;
	struct unpacked_tlv *mgmtadd;
} rxmanifest;

struct agentrx {
	u8 *framein;
	u16 sizein;
	u8 state;
	u8 badFrame;
	u8 rcvFrame;
	u8 rxInfoAge;
	u8 remoteChange;
	u8 tooManyNghbrs;
	u8 dupTlvs;
	u8 dcbx_st;
	bool newNeighbor;
	rxmanifest *manifest;
};

enum agentAdminStatus {
	disabled,
	enabledTxOnly,
	enabledRxOnly,
	enabledRxTx,
};

/* lldp agent specific structure as in chapter 9.2.5
 * of IEEE 802.1AB-2009 */
struct lldp_agent {
	int	adminStatus;

	int	pad;

	u8	mac_addr[ETH_ALEN];

	struct	agentrx rx;
	struct	agenttx tx;
	struct	agentstats stats;
	struct	agenttimers timers;
	u8	rxChanges;
	u16	lldpdu;
	struct	msap msap;

	enum	agent_type type;

        LIST_ENTRY(lldp_agent) entry;
};

struct lldp_agent *lldp_agent_find_by_type(const char *, enum agent_type);
int lldp_add_agent(const char *ifname, enum agent_type);

void set_lldp_agent_admin(const char *ifname, int type, int enable);
int get_lldp_agent_admin(const char *ifname, int type);
int get_lldp_agent_statistics(const char *ifname, struct agentstats *, int);

const char *agent_type2section(int agenttype);

int start_lldp_agents(void);
void stop_lldp_agents(void);
void clean_lldp_agents(void);

#endif /* AGENT_H */
