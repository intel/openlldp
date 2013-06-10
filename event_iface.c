/******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

  Implementation of peer netlink interface
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>
	     Stefan Berger <stefanb at linux.vnet.ibm.com>
	     Gerhard Stenzel <gstenzel at linux.vnet.ibm.com>
	     Thomas Richter <tmricht at linux.vnet.ibm.com>

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

******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include "linux/if.h"
#include "linux/if_vlan.h"
#include "linux/rtnetlink.h"
#include "linux/if_link.h"
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
#include "qbg_vdpnl.h"
#include "lldp_tlv.h"

extern unsigned int if_nametoindex(const char *);
extern char *if_indextoname(unsigned int, char *);

static int peer_sock;

static void event_if_decode_rta(int type, struct rtattr *rta, int *ls, char *d)
{
	switch (type) {
	case IFLA_ADDRESS:
		LLDPAD_DBG(" IFLA_ADDRESS\n");
		break;
	case IFLA_BROADCAST:
		LLDPAD_DBG(" IFLA_BROADCAST\n");
		break;
	case IFLA_IFNAME:
		strncpy(d, (char *)RTA_DATA(rta), IFNAMSIZ);
		LLDPAD_DBG(" IFLA_IFNAME\n");
		LLDPAD_DBG("        device name is %s\n", d);
		break;
	case IFLA_MTU:
		LLDPAD_DBG(" IFLA_MTU\n");
		break;
	case IFLA_LINK:
		LLDPAD_DBG(" IFLA_LINK\n");
		break;
	case IFLA_QDISC:
		LLDPAD_DBG(" IFLA_QDISC\n");
		break;
	case IFLA_STATS:
		LLDPAD_DBG(" IFLA_STATS\n");
		break;
	case IFLA_COST:
		LLDPAD_DBG(" IFLA_COST\n");
		break;
	case IFLA_PRIORITY:
		LLDPAD_DBG(" IFLA_PRIORITY\n");
		break;
	case IFLA_MASTER:
		LLDPAD_DBG(" IFLA_MASTER\n");
		break;
	case IFLA_WIRELESS:
		LLDPAD_DBG(" IFLA_WIRELESS\n");
		break;
	case IFLA_PROTINFO:
		LLDPAD_DBG(" IFLA_PROTINFO\n");
		break;
	case IFLA_TXQLEN:
		LLDPAD_DBG(" IFLA_TXQLEN\n");
		break;
	case IFLA_MAP:
		LLDPAD_DBG(" IFLA_MAP\n");
		break;
	case IFLA_WEIGHT:
		LLDPAD_DBG(" IFLA_WEIGHT\n");
		break;
	case IFLA_OPERSTATE:
		LLDPAD_DBG(" IFLA_OPERSTATE\n");
		*ls = (*((int *)RTA_DATA(rta)));
		LLDPAD_DBG("        OPERSTATE = 0x%02x\n", *ls);
		break;
	case IFLA_LINKMODE:
		LLDPAD_DBG(" IFLA_LINKMODE\n");
		LLDPAD_DBG("        LINKMODE = %s\n", (*((int *)RTA_DATA(rta)))?
			"IF_LINK_MODE_DORMANT": "IF_LINK_MODE_DEFAULT");
		break;
	case IFLA_LINKINFO:
		LLDPAD_DBG(" IFLA_LINKINFO\n");
		break;
	case IFLA_NET_NS_PID:
		LLDPAD_DBG(" IFLA_NET_NS_PID\n");
		break;
	case IFLA_IFALIAS:
		LLDPAD_DBG(" IFLA_IFALIAS\n");
		break;
	case IFLA_NUM_VF:
		LLDPAD_DBG(" IFLA_NUMVF\n");
		break;
	case IFLA_VFINFO_LIST:
		LLDPAD_DBG(" IFLA_VFINFO_LIST\n");
		break;
	case IFLA_STATS64:
		LLDPAD_DBG(" IFLA_STATS64\n");
		break;
	case IFLA_VF_PORTS:
		LLDPAD_DBG(" IFLA_VF_PORTS\n");
		break;
	case IFLA_PORT_SELF:
		LLDPAD_DBG(" IFLA_PORT_SELF\n");
		break;
	case IFLA_AF_SPEC:
		LLDPAD_DBG(" IFLA_AF_SPEC\n");
		break;
	case IFLA_GROUP:
		LLDPAD_DBG(" IFLA_GROUP\n");
		break;
	case IFLA_NET_NS_FD:
		LLDPAD_DBG(" IFLA_NET_NS_FD\n");
		break;
	case IFLA_EXT_MASK:
		LLDPAD_DBG(" IFLA_EXT_MASK\n");
		break;
	case IFLA_PROMISCUITY:
		LLDPAD_DBG(" IFLA_PROMISCUITY\n");
		break;
	case IFLA_NUM_TX_QUEUES:
		LLDPAD_DBG(" IFLA_NUM_TX_QUEUES\n");
		break;
	case IFLA_NUM_RX_QUEUES:
		LLDPAD_DBG(" IFLA_NUM_RX_QUEUES\n");
		break;
	case IFLA_CARRIER:
		LLDPAD_DBG(" IFLA_CARRIER\n");
		break;
	default:
		LLDPAD_DBG(" unknown type : 0x%02x\n", type);
		break;
	}
}

int oper_add_device(char *device_name)
{
	struct lldp_module *np;
	struct port *port, *newport;
	struct lldp_agent *agent;
	int ifindex;

	ifindex = get_ifidx(device_name);
	for (port = porthead; port; port = port->next)
		if (ifindex == port->ifindex)
			break;

	if (!port) {
		newport = add_port(ifindex, device_name);
		if (!newport) {
			LLDPAD_INFO("%s: Error adding device %s\n",
				    __func__, device_name);
			return -EINVAL;
		}

		LLDPAD_INFO("%s: Adding device %s\n", __func__, device_name);
		port = newport;
	} else if (is_bond(device_name) || !port->portEnabled)
		reinit_port(device_name);

	lldp_add_agent(device_name, NEAREST_BRIDGE);
	lldp_add_agent(device_name, NEAREST_NONTPMR_BRIDGE);
	lldp_add_agent(device_name, NEAREST_CUSTOMER_BRIDGE);

	LIST_FOREACH(agent, &port->agent_head, entry) {
		LLDPAD_DBG("%s: calling ifup for agent %p.\n",
			   __func__, agent);
		LIST_FOREACH(np, &lldp_head, lldp) {
			if (np->ops->lldp_mod_ifup)
				np->ops->lldp_mod_ifup(device_name, agent);
		}
	}

	set_lldp_port_enable(device_name, 1);
	return 0;
}

static void event_if_decode_nlmsg(int route_type, void *data, int len)
{
	struct lldp_module *np;
	const struct lldp_mod_ops *ops;
	struct rtattr *rta;
	char device_name[IFNAMSIZ];
	struct lldp_agent *agent;
	int ifindex;
	int attrlen;
	int valid;
	int link_status = IF_OPER_UNKNOWN;

	switch (route_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_SETLINK:
	case RTM_GETLINK:
		ifindex = ((struct ifinfomsg *)data)->ifi_index;
		LLDPAD_DBG(" IFINFOMSG\n");
		LLDPAD_DBG("        ifi_family = 0x%02x\n",
			((struct ifinfomsg *)data)->ifi_family);
		LLDPAD_DBG("        ifi_type   = 0x%x\n",
			((struct ifinfomsg *)data)->ifi_type);
		LLDPAD_DBG("        ifi_index  = %i\n", ifindex);
		LLDPAD_DBG("        ifi_flags  = 0x%04x\n",
			((struct ifinfomsg *)data)->ifi_flags);
		LLDPAD_DBG("        ifi_change = 0x%04x\n",
			((struct ifinfomsg *)data)->ifi_change);

		/* print attributes */
		rta = IFLA_RTA(data);

		attrlen = len - sizeof(struct ifinfomsg);
		while (RTA_OK(rta, attrlen)) {
			event_if_decode_rta(rta->rta_type, rta,
					    &link_status, device_name);
			rta = RTA_NEXT(rta, attrlen);
		}

		LLDPAD_DBG("        link status: %i\n", link_status);
		LLDPAD_DBG("        device name: %s\n", device_name);

		switch (link_status) {
		case IF_OPER_DOWN:
			LLDPAD_DBG("******* LINK DOWN: %s\n", device_name);

			valid = is_valid_lldp_device(device_name);
			if (!valid)
				break;

			struct port *port = port_find_by_ifindex(ifindex);
			if (!port)
				break;

			LIST_FOREACH(agent, &port->agent_head, entry) {
				LLDPAD_DBG("%s: calling ifdown for agent %p.\n",
					   __func__, agent);
				LIST_FOREACH(np, &lldp_head, lldp) {
					ops = np->ops;
					if (ops->lldp_mod_ifdown)
						ops->lldp_mod_ifdown(device_name,
								     agent);
				}
			}

			/* Disable Port */
			set_lldp_port_enable(device_name, 0);

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
			LLDPAD_DBG("******* LINK STATUS %d: %s\n",
				   link_status, device_name);
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
	LLDPAD_DBG("%s:%s: nlmsg_type: %d\n", __FILE__, __FUNCTION__, nlmsg->nlmsg_type);
	event_if_decode_nlmsg(nlmsg->nlmsg_type, NLMSG_DATA(nlmsg),
		NLMSG_PAYLOAD(nlmsg, 0));
}

int event_trigger(struct nlmsghdr *nlh, pid_t pid)
{
	struct sockaddr_nl dest_addr;
	int dest_addrlen = sizeof dest_addr, rc;

	memset(&dest_addr, 0, dest_addrlen);
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = pid;

	rc = sendto(peer_sock, (void *)nlh, nlh->nlmsg_len, 0,
			 (struct sockaddr *) &dest_addr, dest_addrlen);
	LLDPAD_DBG("%s rc:%d pid:%d sender-pid:%d msgsize:%d\n",
		   __func__, rc, pid, nlh->nlmsg_pid, nlh->nlmsg_len);
	return rc;
}

static void
event_iface_receive_user_space(int sock,
			       UNUSED void *eloop_ctx, UNUSED void *sock_ctx)
{
	struct sockaddr_nl dest_addr;
	unsigned char buf[MAX_PAYLOAD];
	socklen_t fromlen = sizeof(dest_addr);
	int result;

	LLDPAD_DBG("Waiting for message\n");
	result = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
		       (struct sockaddr *) &dest_addr, &fromlen);
	if(result < 0) {
		LLDPAD_ERR("%s:receive error on netlink socket:%d\n", __func__,
			    errno);
		return;
	}
	LLDPAD_DBG("%s:recvfrom received %d bytes from pid %d\n", __func__,
		   result, dest_addr.nl_pid);
	result = vdpnl_recv(buf, sizeof buf);
	if (result > 0) {		/* Data to send back */
		result = sendto(sock, buf, result, 0,
				(struct sockaddr *) &dest_addr, fromlen);
		if (result < 0)
			LLDPAD_ERR("%s:send error on netlink socket:%d\n",
				   __func__, errno);
		else
			LLDPAD_DBG("%s:sentto pid %d bytes:%d\n", __func__,
				   dest_addr.nl_pid, result);
	}
}

static void
event_iface_receive(int sock, UNUSED void *eloop_ctx, UNUSED void *sock_ctx)
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

	LLDPAD_DBG("%s:%s result from receive: %d.\n",
		   __FILE__, __FUNCTION__, result);

	/* userspace messages handled in event_iface_receive_user_space() */
	if (dest_addr.nl_pid != 0)
		return;

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

int event_iface_init_user_space()
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
	snl.nl_pid = getpid();  /* self pid */
	snl.nl_groups = 0;

	if (bind(fd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
		close(fd);
		LLDPAD_ERR("Error binding to netlink socket (%s) !\n", strerror(errno));
		return -EIO;
	}

	peer_sock = fd;

	LLDPAD_DBG("%s(%i): socket %i.\n", __func__, __LINE__, peer_sock);

	return eloop_register_read_sock(fd, event_iface_receive_user_space,
					NULL, NULL);
}

int event_iface_deinit()
{
	int rc;

	rc = fcntl(peer_sock, F_GETFD);
	if (rc != -1) {
		rc = close(peer_sock);
		if (rc)
			LLDPAD_ERR("Failed to close fd - %s\n",
					strerror(errno));
	}

	return 0;
}
