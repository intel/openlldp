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

#ifndef PORTS_H
#define PORTS_H

#include <sys/queue.h>
#include <string.h>
#include "lldp.h"
#include "agent.h"

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
#define FAST_TX_INTERVAL        1
#define TX_FAST_INIT            4
#define DEFAULT_TX_DELAY        1
#define FASTSTART_TX_DELAY      1
#define REINIT_DELAY            2
#define TX_CREDIT_MAX           5

#define DORMANT_DELAY	15

struct porttimers {
	u16 dormantDelay;
};

struct eth_hdr {
	char dst[6];
	char src[6];
	u16 ethertype;
};

enum portEnableStatus {
	no = 0,
	yes,
};

/* lldp port specific structure */
struct port {
	char *ifname;
	u8 hw_resetting;
	u8 portEnabled;
	u8 prevPortEnabled;
	u8 bond_master;		/* True if a bond master */
	struct porttimers *timers;

	u16 dormantDelay;

	LIST_HEAD(agent_head, lldp_agent) agent_head;
	struct l2_packet_data *l2;

	struct port *next;
};

extern struct port *porthead;

#ifdef __cplusplus
extern "C" {
#endif
struct port *add_port(const char *);
int remove_port(char *);
#ifdef __cplusplus
}
#endif
int set_port_hw_resetting(const char *ifname, int resetting);
int get_port_hw_resetting(const char *ifname);
void set_lldp_port_enable(const char *ifname, int enable);

int get_local_tlvs(char *ifname, int type, unsigned char *tlvs, int *size);
int get_neighbor_tlvs(char *ifname, int type, unsigned char *tlvs, int *size);

int port_needs_shutdown(struct port *port);

void set_port_operstate(const char *ifname, int operstate);
int get_port_operstate(const char *ifname);

void set_port_oper_delay(const char *ifname);

int reinit_port(const char *ifname);
void set_agent_oper_delay(const char *ifname, int type);

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
