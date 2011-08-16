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
#include <string.h>
#include "states.h"
#include "lldp_tlv.h"
#include "ports.h"
#include "l2_packet.h"
#include "libconfig.h"
#include "lldp_mand_clif.h"
#include "lldp.h"
#include "config.h"
#include "messages.h"
#include "clif_msgs.h"
#include "lldp_rtnl.h"
#include "lldp_dcbx_nl.h"

struct port *porthead = NULL; /* Head pointer */
struct port *portcurrent = NULL; /* Working  pointer loaded from ports or
				  * port->next */

void agent_receive(void *, const u8 *, const u8 *, size_t);

/* Port routines used for command processing -- return cmd_xxx codes */

int get_lldp_port_statistics(char *ifname, struct portstats *stats)
{
	struct port *port;

	port = port_find_by_name(ifname);
	if (!port)
		return cmd_device_not_found;
	memcpy((void *)stats, (void *)&port->stats, sizeof(struct portstats));
	return cmd_success;
}

int get_local_tlvs(char *ifname, unsigned char *tlvs, int *size)
{
	struct port *port;

	port = port_find_by_name(ifname);
	if (!port)
		return cmd_device_not_found;

	if (port->tx.frameout == NULL) {
		*size = 0;
		return cmd_success;
	}

	*size = port->tx.sizeout - sizeof(struct l2_ethhdr);
	if (*size < 0)
		return cmd_invalid;
	memcpy((void *)tlvs,
	       (void *)port->tx.frameout + sizeof(struct l2_ethhdr), *size);

	return cmd_success;
}

int get_neighbor_tlvs(char *ifname, unsigned char *tlvs, int *size)
{
	struct port *port;

	port = port_find_by_name(ifname);
	if (!port)
		return cmd_device_not_found;

	if (port->rx.framein == NULL) {
		*size = 0;
		return cmd_success;
	}

	*size = port->rx.sizein - sizeof(struct l2_ethhdr);
	if (*size < 0)
		return cmd_invalid;
	memcpy((void *)tlvs,
	       (void *)port->rx.framein + sizeof(struct l2_ethhdr), *size);
	return cmd_success;
}

/* Routines used for managing interfaces -- return std C return values */

int get_lldp_port_admin(const char *ifname)
{
	struct port *port = NULL;

	port = porthead;
	while (port != NULL) {
		if (!strncmp(ifname, port->ifname, IFNAMSIZ))
			return port->adminStatus;
		port = port->next;
	}
	return disabled;
}

void set_lldp_port_admin(const char *ifname, int admin)
{
	struct port *port = NULL;
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
						      ARG_ADMINSTATUS,
			                             (void *)&tmp,
						      CONFIG_TYPE_INT))) {
				port = port->next;
				continue;
			}

			if (port->adminStatus != admin) {
				port->adminStatus = admin;
				somethingChangedLocal(ifname);
				run_tx_sm(port);
				run_rx_sm(port);
			}

			if (!all)
				break;
		}
		port = port->next;
	}
}

void set_lldp_port_enable_state(const char *ifname, int enable)
{
	struct port *port = NULL;

	port = port_find_by_name(ifname);

	if (port == NULL)
		return;

	port->portEnabled = (u8)enable;

	if (!enable) /* port->adminStatus = disabled; */
		port->rx.rxInfoAge = false;

	run_tx_sm(port);
	run_rx_sm(port);
}

void set_port_oper_delay(const char *ifname)
{
	struct port *port = port_find_by_name(ifname);

	if (port == NULL)
		return;

	port->timers.dormantDelay = DORMANT_DELAY;
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
	struct port *port;

	port = port_find_by_name(ifname);

	if (!port)
		return -1;

	/* Reset relevant port variables */
	port->tx.state  = TX_LLDP_INITIALIZE;
	port->timers.state  = TX_TIMER_BEGIN;
	port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
	port->hw_resetting = false;
	port->portEnabled = false;
	port->tx.txTTL = 0;
	port->msap.length1 = 0;
	port->msap.msap1 = NULL;
	port->msap.length2 = 0;
	port->msap.msap2 = NULL;
	port->lldpdu = false;
	port->timers.dormantDelay = DORMANT_DELAY;

	/* init & enable RX path */
	rxInitializeLLDP(port);

	/* init TX path */
	txInitializeTimers(port);
	txInitializeLLDP(port);

	return 0;
}

int add_port(const char *ifname)
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
	newport->tx.state  = TX_LLDP_INITIALIZE;
	newport->timers.state = TX_TIMER_BEGIN;
	newport->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
	newport->hw_resetting = false;
	newport->portEnabled = false;

	if (get_config_setting(newport->ifname, ARG_ADMINSTATUS,
			(void *)&newport->adminStatus, CONFIG_TYPE_INT))
			newport->adminStatus = disabled;

	newport->tx.txTTL = 0;
	newport->msap.length1 = 0;
	newport->msap.msap1 = NULL;
	newport->msap.length2 = 0;
	newport->msap.msap2 = NULL;
	newport->lldpdu = false;
	newport->timers.dormantDelay = DORMANT_DELAY;

	/* init & enable RX path */
	rxInitializeLLDP(newport);
	newport->l2 = l2_packet_init(newport->ifname, NULL, ETH_P_LLDP,
		rxReceiveFrame, newport, 1);
	if (newport->l2 == NULL) {
		LLDPAD_DBG("Failed to open register layer 2 access to "
			"ETH_P_LLDP\n");
		goto fail;
	}

	/* init TX path */
	txInitializeTimers(newport);
	txInitializeLLDP(newport);

	/* enable TX path */
	if (porthead)
		newport->next = porthead;

	porthead = newport;
	return 0;

fail:
	if(newport) {
		if(newport->ifname)
			free(newport->ifname);
		free(newport);
	}
	return -1;
}

int remove_port(const char *ifname)
{
	struct port *port = NULL;    /* Pointer to port to remove */
	struct port *parent = NULL;  /* Pointer to previous on port stack */

	port = port_find_by_name(ifname);

	if (port == NULL) {
		LLDPAD_DBG("remove_port: port not present\n");
		return -1;
	}

	/* Set linkmode to off */
	set_linkmode(ifname, 0);

	/* Close down the socket */
	l2_packet_deinit(port->l2);

	/* Re-initialize relevant port variables */
	port->tx.state = TX_LLDP_INITIALIZE;
	port->timers.state = TX_TIMER_BEGIN;
	port->rx.state = LLDP_WAIT_PORT_OPERATIONAL;
	port->portEnabled  = false;
	port->adminStatus  = disabled;
	port->tx.txTTL = 0;

	/* Take this port out of the chain */
	if (parent == NULL)
		porthead = port->next;
	else if (parent->next == port) /* Sanity check */
		parent->next = port->next;
	else
		return -1;

	/* Remove the tlvs */
	if (port->msap.msap1) {
		free(port->msap.msap1);
		port->msap.msap1 = NULL;
	}

	if (port->msap.msap2) {
		free(port->msap.msap2);
		port->msap.msap2 = NULL;
	}

	if (port->rx.framein)
		free(port->rx.framein);

	if (port->tx.frameout)
		free(port->tx.frameout);

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
