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
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include "eloop.h"
#include "ports.h"
#include "messages.h"
#include "l2_packet.h"
#include "lldp_util.h"
#include "dcb_types.h"
#include "lldp/states.h"
#include "lldp_dcbx_nl.h"

struct l2_packet_data {
	int fd;
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	u8 perm_mac_addr[ETH_ALEN];
	u8 curr_mac_addr[ETH_ALEN];
	u8 san_mac_addr[ETH_ALEN];
	u8 remote_mac_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, int ifindex,
			    const u8 *buf, size_t len);
	void *rx_callback_ctx;
	int l2_hdr; /* whether to include layer 2 (Ethernet) header data
		     * buffers */
};

int l2_packet_get_own_src_addr(struct l2_packet_data *l2, u8 *addr)
{
	if (is_san_mac(l2->san_mac_addr))
		memcpy(addr, l2->san_mac_addr, ETH_ALEN);
	else {
		/* get an appropriate src MAC to use if the port is
	 	* part of a bond.
		*/
		struct port *bond_port = porthead;
		while (bond_port != NULL) {
			if (bond_port->bond_master
			    && get_src_mac_from_bond(bond_port, l2->ifname,
						     addr))
				return 0;

			bond_port = bond_port->next;
		}
		memcpy(addr, l2->curr_mac_addr, ETH_ALEN);
	}

	return 0;
}


/*
 * Extracts the remote peer's MAC address from the rx frame  and
 * puts it in the l2_packet_data
 */
void get_remote_peer_mac_addr(struct port *port, struct lldp_agent *agent)
{
	int offset = ETH_ALEN;  /* points to remote MAC address in RX frame */
	memcpy(port->l2->remote_mac_addr, &agent->rx.framein[offset], ETH_ALEN);
}

void l2_packet_get_remote_addr(struct l2_packet_data *l2, u8 *addr)
{
	memcpy(addr, l2->remote_mac_addr, ETH_ALEN);
}

int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr)
{
	memcpy(addr, l2->perm_mac_addr, ETH_ALEN);
	return 0;
}

int l2_packet_send(struct l2_packet_data *l2, const u8 *dst_addr, u16 proto,
		   const u8 *buf, size_t len)
{
	int ret;
	if (l2 == NULL)
		return -1;

	if (l2->l2_hdr) {
		ret = send(l2->fd, buf, len, 0);
		if (ret < 0)
			perror("l2_packet_send - send");
	} else {
		struct sockaddr_ll ll;
		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = l2->ifindex;
		ll.sll_protocol = htons(proto);
		ll.sll_halen = ETH_ALEN;
		memcpy(ll.sll_addr, dst_addr, ETH_ALEN);
		ret = sendto(l2->fd, buf, len, 0, (struct sockaddr *) &ll,
			     sizeof(ll));
		if (ret < 0)
			perror("l2_packet_send - sendto");
	}
	return ret;
}


static void l2_packet_receive(int sock, void *eloop_ctx, UNUSED void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	u8 buf[2300];
	int res;
	struct sockaddr_ll ll;
	socklen_t fromlen;

	memset(&ll, 0, sizeof(ll));
	fromlen = sizeof(ll);
	res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &ll,
		       &fromlen);

	if (res < 0) {
		LLDPAD_INFO("receive ERROR = %d\n", res);
		perror("l2_packet_receive - recvfrom");
		return;
	}

	l2->rx_callback(l2->rx_callback_ctx, ll.sll_ifindex, buf, res);
}


struct l2_packet_data * l2_packet_init(
	const char *ifname, UNUSED const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, int ifindex,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	l2 = malloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
	memset(l2, 0, sizeof(*l2));
	strncpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;

	l2->fd = socket(PF_PACKET, l2_hdr ? SOCK_RAW : SOCK_DGRAM,
			htons(protocol));

	if (l2->fd < 0) {
		perror("socket(PF_PACKET)");
		free(l2);
		return NULL;
	}

	strncpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));
	if (ioctl(l2->fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		close(l2->fd);
		free(l2);
		return NULL;
	}
	l2->ifindex = ifr.ifr_ifindex;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	if (bind(l2->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET]");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	/* current hw address */
	if (ioctl(l2->fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		close(l2->fd);
		free(l2);
		return NULL;
	}
	memcpy(l2->curr_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (get_perm_hwaddr(ifname, l2->perm_mac_addr, l2->san_mac_addr) != 0) {
		memcpy(l2->perm_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		memset(l2->san_mac_addr, 0xff, ETH_ALEN);
	}
	LLDPAD_DBG("%s mac:" MACSTR " perm:" MACSTR " san:" MACSTR "\n",
		   ifname, MAC2STR(l2->curr_mac_addr),
		   MAC2STR(l2->perm_mac_addr), MAC2STR(l2->san_mac_addr));

	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = l2->ifindex;
	mr.mr_alen = ETH_ALEN;
	memcpy(mr.mr_address, &nearest_bridge, ETH_ALEN);
	mr.mr_type = PACKET_MR_MULTICAST;
	if (setsockopt(l2->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0) {
		perror("setsockopt nearest_bridge");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	memcpy(mr.mr_address, &nearest_customer_bridge, ETH_ALEN);
	if (setsockopt(l2->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		       sizeof(mr)) < 0)
		perror("setsockopt nearest_customer_bridge");

	memcpy(mr.mr_address, &nearest_nontpmr_bridge, ETH_ALEN);
	if (setsockopt(l2->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		       sizeof(mr)) < 0)
		perror("setsockopt nearest_nontpmr_bridge");

	int option = 1;
	int option_size = sizeof(option);
	if (setsockopt(l2->fd, SOL_PACKET, PACKET_ORIGDEV,
		&option, option_size) < 0) {
		perror("setsockopt SOL_PACKET");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	option = TC_PRIO_CONTROL;
	if ( setsockopt(l2->fd, SOL_SOCKET, SO_PRIORITY, &option,
		sizeof(option_size)) < 0) {
		perror("setsockopt SOL_PRIORITY");
		close(l2->fd);
		free(l2);
		return NULL;
	}

	LLDPAD_INFO("%s MAC address is " MACSTR "\n",
		ifname, MAC2STR(l2->perm_mac_addr));

	eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);

	return l2;
}


void l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	if (l2->fd >= 0) {
		eloop_unregister_read_sock(l2->fd);
		close(l2->fd);
	}
		
	free(l2);
}
