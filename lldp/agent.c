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
#include "ports.h"
#include "eloop.h"
#include "states.h"
#include "lldp_tlv.h"
#include "messages.h"
#include "lldp/l2_packet.h"
#include "lldp_mod.h"
#include "config.h"
#include "lldp_mand_clif.h"
#include "lldp/agent.h"

static const u8 * agent_groupmacs[AGENT_MAX] = {
	nearest_bridge,
	nearest_nontpmr_bridge,
	nearest_customer_bridge,
};

static const char *agent_sections[AGENT_MAX] = {
	[NEAREST_BRIDGE] = "nearest_bridge",
	[NEAREST_NONTPMR_BRIDGE] = "nearest_nontpmr_bridge",
	[NEAREST_CUSTOMER_BRIDGE] = "nearest_customer_bridge",
};

struct lldp_agent *
lldp_agent_find_by_type(const char *ifname, enum agent_type type)
{
	struct port *port;
	struct lldp_agent *agent;

	port = port_find_by_name(ifname);

	if (port == NULL)
		return NULL;

	LIST_FOREACH(agent, &port->agent_head, entry) {
		if (agent->type == type)
			return agent;
	}

	return NULL;
}

const char *agent_type2section(int agenttype)
{
	if ((agenttype > NEAREST_BRIDGE) && (agenttype < AGENT_MAX))
		return agent_sections[agenttype];
	else
		return LLDP_SETTING;
}

void lldp_init_agent(struct port *port, struct lldp_agent *agent, int type)
{
	char macstring[30];

	memset(agent, 0, sizeof(struct lldp_agent));

	memcpy(&agent->mac_addr, agent_groupmacs[type], ETH_ALEN);

	mac2str(agent->mac_addr, macstring, 30);
	LLDPAD_DBG("%s: creating new agent for %s (%s).\n", __func__,
		   port->ifname, macstring);

	/* Initialize relevant agent variables */
	agent->tx.state  = TX_LLDP_INITIALIZE;
	agent->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
	agent->type = type;

	if (get_config_setting(port->ifname, type, ARG_ADMINSTATUS,
			(void *)&agent->adminStatus, CONFIG_TYPE_INT)) {
		LLDPAD_DBG("%s: agent->adminStatus = disabled.\n", __func__);
		agent->adminStatus = disabled;
	}

	/* init & enable RX path */
	rxInitializeLLDP(port, agent);

	/* init TX path */
	txInitializeTimers(agent);
	txInitializeLLDP(agent);
}

int lldp_add_agent(const char *ifname, enum agent_type type)
{
	int count;
	struct port *port;
	struct lldp_agent *agent, *newagent;

	port = port_find_by_name(ifname);

	if (port == NULL)
		return -1;

	/* check if lldp_agents for this if already exist */
	count = 0;
	LIST_FOREACH(agent, &port->agent_head, entry) {
		count++;
		if (agent->type != type)
			continue;
		else
			return -1;
	}

	/* if not, create one and initialize it */
	LLDPAD_DBG("%s(%i): creating new agent for port %s.\n", __func__,
		   __LINE__, ifname);
	newagent  = (struct lldp_agent *)malloc(sizeof(struct lldp_agent));
	if (newagent == NULL) {
		LLDPAD_DBG("%s(%i): creation of new agent failed !.\n",
			   __func__,  __LINE__);
		return -1;
	}

	lldp_init_agent(port, newagent, type);

	LIST_INSERT_HEAD(&port->agent_head, newagent, entry);

	LLDPAD_DBG("%s: %i agents on if %s.\n", __func__, count, port->ifname);

	return 0;
}

static void timer(UNUSED void *eloop_data, UNUSED void *user_ctx)
{
	struct lldp_module *n;
	struct lldp_agent *agent;
	struct port *port = porthead;

	while (port != NULL) {
		/* execute rx and tx sm for all agents on a port */
		LIST_FOREACH(agent, &port->agent_head, entry) {
			char macstring[30];
			mac2str(&agent->mac_addr[0], macstring, 29);

			update_tx_timers(agent);
			run_tx_timers_sm(port, agent);
			run_tx_sm(port, agent);
			run_rx_sm(port, agent);
			update_rx_timers(agent);

			LIST_FOREACH(n, &lldp_head, lldp) {
				if (n->ops && n->ops->timer)
					n->ops->timer(port, agent);
			}
		}

		if (port->dormantDelay)
			port->dormantDelay--;

		port = port->next;
	};

	/* Load new timer */
	eloop_register_timeout(1, 0, timer, NULL, NULL);
}

int start_lldp_agents(void)
{
	eloop_register_timeout(1, 0, timer, NULL, NULL);
	return 1;
}

void stop_lldp_agents(void)
{
	eloop_cancel_timeout(timer, NULL, NULL);
}

void clean_lldp_agents(void)
{
	struct port *port = porthead;
	struct lldp_agent *agent;

	while (port != NULL) {
		if (port_needs_shutdown(port)) {
			LLDPAD_DBG("Send shutdown frame on port %s\n",
				port->ifname);
			LIST_FOREACH(agent, &port->agent_head, entry) {
				process_tx_shutdown_frame(port, agent);
			}
		} else {
			LLDPAD_DBG("No shutdown frame is sent on port %s\n",
				port->ifname);
		}
		port = port->next;
	}
}
