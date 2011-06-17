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

#ifndef PORTS_H
#define PORTS_H

#include <string.h>
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

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define MAX_INTERFACES          16

#define DEFAULT_TX_HOLD         4
#define DEFAULT_TX_INTERVAL     30
#define FASTSTART_TX_INTERVAL   1
#define FASTSTART_TX_COUNT      5
#define DEFAULT_TX_DELAY        1
#define FASTSTART_TX_DELAY      1
#define REINIT_DELAY            2

#define DORMANT_DELAY	15

struct porttimers {
	u16 dormantDelay;
/* Tx */
	u16 reinitDelay;
	u16 msgTxHold;
	u16 msgTxInterval;
	u16 txDelay;
	u16 txTTR;
	u16 txShutdownWhile;
	u16 txDelayWhile;
/* Rx */
	u16 tooManyNghbrsTimer;
	u16 rxTTL;
	u16 lastrxTTL;  /* cache last received */
};

struct porttx {
	u8 *frameout;
	u32 sizeout;
	u8 state;
	u8 localChange;
	u16 txTTL;
};

struct portstats {
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
}rxmanifest;

struct portrx {
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
	rxmanifest *manifest;
};

struct eth_hdr {
	char dst[6];
	char src[6];
	u16 ethertype;
};

enum portAdminStatus {
	disabled,
	enabledTxOnly,
	enabledRxOnly,
	enabledRxTx,
};

struct port {
	char *ifname;
	u8 hw_resetting;
	u8 portEnabled;
	u8 prevPortEnabled;
	u8 adminStatus;

	/* protocol specific */
	struct l2_packet_data *l2;
	struct portrx rx;
	struct porttx tx;
	struct portstats stats;
	struct porttimers timers;
	u8 rxChanges;
	u16   lldpdu;
	struct msap msap;

	struct port *next;
};

extern struct port *porthead;
extern struct port *portcurrent;
extern struct port *porttail;

#ifdef __cplusplus
extern "C" {
#endif
int add_port(const char *);
int remove_port(const char *);
#ifdef __cplusplus
}
#endif
int set_port_hw_resetting(const char *ifname, int resetting);
int get_port_hw_resetting(const char *ifname);
void set_lldp_port_enable_state(const char *ifname, int enable);
void set_lldp_port_admin(const char *ifname, int enable);
int get_lldp_port_admin(const char *ifname);

int get_lldp_port_statistics(char *ifname, struct portstats *stats);

int get_local_tlvs(char *ifname, unsigned char *tlvs, int *size);
int get_neighbor_tlvs(char *ifname, unsigned char *tlvs, int *size);

int port_needs_shutdown(struct port *port);

void set_port_operstate(const char *ifname, int operstate);
int get_port_operstate(const char *ifname);

int reinit_port(const char *ifname);
void set_port_oper_delay(const char *ifname);

static inline struct port *port_find_by_name(const char *ifname)
{
	struct port *port = porthead;

	while (port) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ))
			return port;
		port = port->next;
	}
	return NULL;
}
#endif /* PORTS_H */
