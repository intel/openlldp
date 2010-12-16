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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <syslog.h>
#include <unistd.h>
#include "lldpad.h"
#include "lldp_mod.h"
#include "eloop.h"
#include "event_iface.h"
#include "lldp_util.h"
#include "config.h"
#include "lldp/l2_packet.h"
#include "config.h"
#include "lldp/states.h"
#include "messages.h"
#include "lldp_rtnl.h"

#define MAX_PAYLOAD 4096 /* maximum payload size */

static void event_if_decode_rta(int type, struct rtattr *rta, int *ls, char *d)
{

	LLDPAD_DBG("    rta_type  =", rta->rta_len);
	
	switch (type) {
	case IFLA_ADDRESS:
		LLDPAD_DBG(" IFLA_ADDRESS\n");
		break;
	case IFLA_BROADCAST:
		LLDPAD_DBG(" IFLA_BROADCAST\n");
		break;
	case IFLA_OPERSTATE:
		LLDPAD_DBG(" IFLA_OPERSTATE ", type);
		*ls = (*((int *)RTA_DATA(rta)));
		break;
	case IFLA_LINKMODE:
		LLDPAD_DBG(" IFLA_LINKMODE  ", type);
		LLDPAD_DBG("        LINKMODE = ", (*((int *)RTA_DATA(rta)))? 
			"IF_LINK_MODE_DORMANT": "IF_LINK_MODE_DEFAULT");
		break;
	case IFLA_IFNAME:
		strncpy(d, (char *)RTA_DATA(rta), IFNAMSIZ);
		LLDPAD_DBG(" IFLA_IFNAME\n");
		LLDPAD_DBG(" device name is ", d);
		break;
	default:
		LLDPAD_DBG(" unknown type : ", type);
		break;
	}
}

int oper_add_device(char *device_name)
{
	struct lldp_module *np;
	const struct lldp_mod_ops *ops;
	struct port *port;
	int err;

	port = porthead;
	while (port != NULL) {
		if (!strncmp(device_name, port->ifname, MAX_DEVICE_NAME_LEN))
			break;
		port = port->next;
	}

	if (!port) {
		if (is_bond(device_name))
			err = add_bond_port(device_name);
		else
			err = add_port(device_name);

		if (err) {
			LLDPAD_INFO("%s: Error adding device %s\n",
				__func__, device_name);
			return err;
		} else
			LLDPAD_INFO("%s: Adding device %s\n",
				__func__, device_name);
	} else if (!port->portEnabled)
		reinit_port(device_name);

	LIST_FOREACH(np, &lldp_head, lldp) {
		ops = np->ops;
		if (ops->lldp_mod_ifup)
			ops->lldp_mod_ifup(device_name);
	}

	set_lldp_port_enable_state(device_name, 1);
	return 0;
}

static void event_if_decode_nlmsg(int route_type, void *data, int len)
{
	struct lldp_module *np;
	const struct lldp_mod_ops *ops;
	struct rtattr *rta;
	char device_name[IFNAMSIZ];
	int attrlen;
	int valid;
	int link_status = IF_OPER_UNKNOWN;

	switch (route_type) {
	case RTM_NEWLINK:		
	case RTM_DELLINK:
	case RTM_SETLINK:
	case RTM_GETLINK:
		LLDPAD_DBG("  IFINFOMSG\n");
		LLDPAD_DBG("  ifi_family = ",
			((struct ifinfomsg *)data)->ifi_family);
		LLDPAD_DBG("  ifi_type   = ",
			((struct ifinfomsg *)data)->ifi_type);
		LLDPAD_DBG("  ifi_index  = ",
			((struct ifinfomsg *)data)->ifi_index);
		LLDPAD_DBG("  ifi_flags  = ",
			((struct ifinfomsg *)data)->ifi_flags);
		LLDPAD_DBG("  ifi_change = ",
			((struct ifinfomsg *)data)->ifi_change);

		/* print attributes */
		rta = IFLA_RTA(data);

		attrlen = len - sizeof(struct ifinfomsg);
		while (RTA_OK(rta, attrlen)) {
			event_if_decode_rta(rta->rta_type, rta,
					    &link_status, device_name);
			rta = RTA_NEXT(rta, attrlen);
		}

		LLDPAD_DBG("link status: ", link_status);
		LLDPAD_DBG("device name: ", device_name);

		switch (link_status) {
		case IF_OPER_DOWN:
			LLDPAD_DBG("******* LINK DOWN: %s\n", device_name);

			valid = is_valid_lldp_device(device_name);
			if (!valid)
				break;

			LIST_FOREACH(np, &lldp_head, lldp) {
				ops = np->ops;
				if (ops->lldp_mod_ifdown)
					ops->lldp_mod_ifdown(device_name);
			}

			/* Disable Port */
			set_lldp_port_enable_state(device_name, 0);

			if (route_type == RTM_DELLINK) {
				LLDPAD_INFO("%s: %s: device removed!\n",
					__func__, device_name);
				remove_port(device_name);
			}
			break;
		case IF_OPER_DORMANT:
			LLDPAD_DBG("******* LINK DORMANT: %s\n", device_name);
			valid = is_valid_lldp_device(device_name);
			if (!valid)
				break;
			set_port_oper_delay(device_name);
			oper_add_device(device_name);
			break;
		case IF_OPER_UP:
			LLDPAD_DBG("******* LINK UP: %s\n", device_name);
			valid = is_valid_lldp_device(device_name);
			if (!valid)
				break;
			oper_add_device(device_name);
			break;
		default:
			break;
		}
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
		LLDPAD_DBG("Address change.\n");
		break;
	default:
		LLDPAD_DBG("No decode for this type\n");
	}
}


static void event_if_process_recvmsg(struct nlmsghdr *nlmsg)
{

	/* print out details */
	event_if_decode_nlmsg(nlmsg->nlmsg_type, NLMSG_DATA(nlmsg),
		NLMSG_PAYLOAD(nlmsg, 0));
}

static void event_iface_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct nlmsghdr *nlh;
	struct sockaddr_nl dest_addr;
	char buf[MAX_PAYLOAD];
	socklen_t fromlen = sizeof(dest_addr);
	int result;
	
	result = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
		       (struct sockaddr *) &dest_addr, &fromlen);

	if (result < 0) {
		perror("recvfrom(Event interface)");
		eloop_register_timeout(INI_TIMER, 0, scan_port, NULL, NULL);
		return;
	}

	LLDPAD_DBG("PRINT BUF info.\n");

	nlh = (struct nlmsghdr *)buf;
	event_if_process_recvmsg(nlh);
}

int event_iface_init()
{
	int fd;
	int rcv_size = MAX_PAYLOAD;
	struct sockaddr_nl snl;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0)
		return fd;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int)) < 0) {
		close(fd);
		return -EIO;
	}

	memset((void *)&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = RTMGRP_LINK;

	if (bind(fd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
		close(fd);
		return -EIO;
	}

	return eloop_register_read_sock(fd, event_iface_receive, NULL, NULL);
}

int event_iface_deinit()
{
	return 0;
}
