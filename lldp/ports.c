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

#include <stdlib.h>
#include <string.h>
#include "states.h"
#include "lldp_tlv.h"
#include "lldp_rtnl.h"
#include "ports.h"
#include "l2_packet.h"
#include "libconfig.h"
#include "lldp_mand_clif.h"
#include "lldp.h"
#include "config.h"
#include "messages.h"
#include "lldpad_status.h"
#include "lldp_rtnl.h"
#include "lldp_dcbx_nl.h"
#include "agent.h"
#include "lldp_dcbx_nl.h"

struct port *porthead = NULL; /* port Head pointer */

void agent_receive(void *, const u8 *, const u8 *, size_t);

/* Port routines used for command processing -- return cmd_xxx codes */

int get_lldp_agent_statistics(const char *ifname, struct agentstats *stats, int type)
{
	struct lldp_agent *agent;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	memcpy((void *)stats, (void *)&agent->stats, sizeof(struct agentstats));

	return 0;
}

int get_local_tlvs(char *ifname, int type, unsigned char *tlvs, int *size)
{
	struct lldp_agent *agent;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	if (agent->tx.frameout == NULL) {
		*size = 0;
		return cmd_success;
	}

	*size = agent->tx.sizeout - sizeof(struct l2_ethhdr);
	if (*size < 0)
		return cmd_invalid;
	memcpy((void *)tlvs,
	       (void *)agent->tx.frameout + sizeof(struct l2_ethhdr), *size);

	return cmd_success;
}

int get_neighbor_tlvs(char *ifname, int type, unsigned char *tlvs, int *size)
{
	struct lldp_agent *agent;

	agent = lldp_agent_find_by_type(ifname, type);
	if (!agent)
		return cmd_agent_not_found;

	if (agent->rx.framein == NULL) {
		*size = 0;
		return cmd_success;
	}

	*size = agent->rx.sizein - sizeof(struct l2_ethhdr);

	if (*size < 0)
		return cmd_invalid;

	memcpy((void *)tlvs,
	       (void *)agent->rx.framein + sizeof(struct l2_ethhdr), *size);

	return cmd_success;
}

/* Routines used for managing interfaces -- return std C return values */

int get_lldp_agent_admin(const char *ifname, int type)
{
	struct lldp_agent *agent = NULL;

	agent = lldp_agent_find_by_type(ifname, type);

	if (agent == NULL)
		return disabled;

	return agent->adminStatus;
}

void set_lldp_agent_admin(const char *ifname, int type, int admin)
{
	struct port *port = NULL;
	struct lldp_agent *agent;
	int all = 0;
	int tmp;

	all = !strlen(ifname);

	port = porthead;
	while (port != NULL) {
		if (all || !strncmp(ifname, port->ifname, IFNAMSIZ)) {
			/* don't change a port which has an explicit setting
			 * on a global setting change
			 */
			if (all && (!get_config_setting(port->ifname,
							type,
							ARG_ADMINSTATUS,
							(void *)&tmp,
							CONFIG_TYPE_INT))) {
				port = port->next;
				continue;
			}

			agent = lldp_agent_find_by_type(port->ifname, type);
			if (!agent) {
				port = port->next;
				continue;
			}

			if (agent->adminStatus != admin) {
				agent->adminStatus = admin;
				somethingChangedLocal(ifname, type);
				run_tx_sm(port, agent);
				run_rx_sm(port, agent);
			}

			if (!all)
				break;
		}
		port = port->next;
	}
}

void set_lldp_port_enable(const char *ifname, int enable)
{
	struct port *port = NULL;
	struct lldp_agent *agent = NULL;

	port = port_find_by_name(ifname);

	if (port == NULL)
		return;

	port->portEnabled = (u8)enable;

	if (!enable) { /* port->adminStatus = disabled; */
		LIST_FOREACH(agent, &port->agent_head, entry) {
			agent->rx.rxInfoAge = false;
		}
	}

	LIST_FOREACH(agent, &port->agent_head, entry) {
		run_tx_sm(port, agent);
		run_rx_sm(port, agent);
	}
}

void set_port_oper_delay(const char *ifname)
{
	struct port *port = port_find_by_name(ifname);

	if (port == NULL)
		return;

	port->dormantDelay = DORMANT_DELAY;

	return;
}

int set_port_hw_resetting(const char *ifname, int resetting)
{
	struct port *port = NULL;

	port = port_find_by_name(ifname);

	if (port == NULL)
		return -1;

	port->hw_resetting = (u8)resetting;

	return port->hw_resetting;
}

int get_port_hw_resetting(const char *ifname)
{
	struct port *port = NULL;

	port = port_find_by_name(ifname);

	if (port)
		return port->hw_resetting;
	else
		return 0;
}

int reinit_port(const char *ifname)
{
	struct lldp_agent *agent;
	struct port *port;

	port = port_find_by_name(ifname);

	if (!port)
		return -1;

	/* Reset relevant port variables */
	port->hw_resetting = false;
	port->portEnabled = false;
	port->dormantDelay = DORMANT_DELAY;

	LIST_FOREACH(agent, &port->agent_head, entry) {
		/* init TX path */

		/* Reset relevant state variables */
		agent->tx.state  = TX_LLDP_INITIALIZE;
		agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		agent->tx.txTTL = 0;
		agent->msap.length1 = 0;
		agent->msap.msap1 = NULL;
		agent->msap.length2 = 0;
		agent->msap.msap2 = NULL;
		agent->lldpdu = false;
		agent->timers.state  = TX_TIMER_BEGIN;

		/* init & enable RX path */
		rxInitializeLLDP(port, agent);

		/* init TX path */
		txInitializeTimers(agent);
		txInitializeLLDP(agent);
	}

	return 0;
}

struct port *add_port(const char *ifname)
{
	struct port *newport;

	newport = porthead;
	while (newport != NULL) {
		if (!strncmp(ifname, newport->ifname, IFNAMSIZ))
			return 0;
		newport = newport->next;
	}

	newport  = (struct port *)malloc(sizeof(struct port));
	if (newport == NULL) {
		LLDPAD_DBG("new port malloc failed\n");
		goto fail;
	}
	memset(newport,0,sizeof(struct port));
	newport->next = NULL;
	newport->ifname = strdup(ifname);
	if (newport->ifname == NULL) {
		LLDPAD_DBG("new port name malloc failed\n");
		goto fail;
	}

	/* Initialize relevant port variables */
	newport->hw_resetting = false;
	newport->portEnabled = false;

	LIST_INIT(&newport->agent_head);

	newport->l2 = l2_packet_init(newport->ifname, NULL, ETH_P_LLDP,
		rxReceiveFrame, newport, 1);
	if (newport->l2 == NULL) {
		LLDPAD_DBG("Failed to open register layer 2 access to "
			"ETH_P_LLDP\n");
		goto fail;
	}

	/* init TX path */
	newport->dormantDelay = DORMANT_DELAY;

	/* enable TX path */
	if (porthead)
		newport->next = porthead;

	porthead = newport;
	return newport;

fail:
	if(newport) {
		if(newport->ifname)
			free(newport->ifname);
		free(newport);
	}
	return NULL;
}

int remove_port(char *ifname)
{
	struct port *port = NULL;    /* Pointer to port to remove */
	struct port *parent = NULL;  /* Pointer to previous on port stack */
	struct lldp_agent *agent = NULL;

	port = port_find_by_name(ifname);

	if (port == NULL) {
		LLDPAD_DBG("remove_port: port not present\n");
		return -1;
	}

	LLDPAD_DBG("In remove_port: Found port %s\n", port->ifname);

	/* Set linkmode to off */
	set_linkmode(ifname, 0);

	/* Close down the socket */
	l2_packet_deinit(port->l2);

	port->portEnabled  = false;

	while (!LIST_EMPTY(&port->agent_head)) {
		agent = LIST_FIRST(&port->agent_head);

		/* Re-initialize relevant port variables */
		agent->tx.state = TX_LLDP_INITIALIZE;
		agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
		agent->timers.state = TX_TIMER_BEGIN;
		agent->adminStatus  = disabled;
		agent->tx.txTTL = 0;

		/* Remove the tlvs */
		if (agent->msap.msap1) {
			free(agent->msap.msap1);
			agent->msap.msap1 = NULL;
		}

		if (agent->msap.msap2) {
			free(agent->msap.msap2);
			agent->msap.msap2 = NULL;
		}

		if (agent->rx.framein)
			free(agent->rx.framein);

		if (agent->tx.frameout)
			free(agent->tx.frameout);

		LIST_REMOVE(agent, entry);
		free(agent);

	}

	/* Take this port out of the chain */
	if (parent == NULL)
		porthead = port->next;
	else if (parent->next == port) /* Sanity check */
		parent->next = port->next;
	else
		return -1;

	if (port->ifname)
		free(port->ifname);

	free(port);

	return 0;
}

/*
 * port_needs_shutdown - check if we need send LLDP shutdown frame on this port
 * @port: the port struct
 *
 * Return 1 for yes and 0 for no.
 *
 * No shutdown frame for port that has dcb enabled
 */
int port_needs_shutdown(struct port *port)
{
	return !check_port_dcb_mode(port->ifname);
}
