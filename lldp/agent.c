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

#include <stdlib.h>
#include "agent.h"
#include "ports.h"
#include "eloop.h"
#include "states.h"
#include "lldp_tlv.h"
#include "messages.h"
#include "lldp/l2_packet.h"
#include "lldp_mod.h"

static void timer(void *eloop_data, void *user_ctx)
{
	struct port *port = porthead;
	struct lldp_module *n;

	while (port != NULL) {
		update_tx_timers(port);
		run_tx_timers_sm(port);
		run_tx_sm(port);
		run_rx_sm(port);
		update_rx_timers(port);
		LIST_FOREACH(n, &lldp_head, lldp) {
			if (n->ops && n->ops->timer)
				n->ops->timer(port);
		}
		if (port->timers.dormantDelay)
			port->timers.dormantDelay--;
		port = port->next;
	};

	/* Load new timer */
	eloop_register_timeout(1, 0, timer, NULL, NULL);
}

int start_lldp_agent(void)
{
	eloop_register_timeout(1, 0, timer, NULL, NULL);
	return 1;
}

void stop_lldp_agent(void)
{
	eloop_cancel_timeout(timer, NULL, NULL);
}

void clean_lldp_agent(void)
{
	struct port *port = porthead;

	while (port != NULL) {
		if (port_needs_shutdown(port)) {
			LLDPAD_DBG("Send shutdown frame on port %s\n",
				port->ifname);
			process_tx_shutdown_frame(port);
		} else {
			LLDPAD_DBG("No shutdown frame is sent on port %s\n",
				port->ifname);
		}
		port = port->next;
	}
}
