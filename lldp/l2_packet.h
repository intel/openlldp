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

#ifndef L2_PACKET_H
#define L2_PACKET_H

#include <stdlib.h>
#include <linux/if_ether.h>
#include "lldp.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define IPSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define ETH_P_LLDP 0x88cc

#define ETH_P_ECP	0x88b7		/* Draft 0.2 */
#define ETH_P_ECP22	0x8940		/* Ratified standard */

#ifndef ETH_MIN_DATA_LEN
#define ETH_MIN_DATA_LEN	(ETH_ZLEN - ETH_HLEN)
#endif

/**
 * struct l2_packet_data - Internal l2_packet data structure
 *
 * This structure is used by the l2_packet implementation to store its private
 * data. Other files use a pointer to this data when calling the l2_packet
 * functions, but the contents of this structure should not be used directly
 * outside l2_packet implementation.
 */
struct l2_packet_data;


struct l2_ethhdr {
	u8 h_dest[ETH_ALEN];
	u8 h_source[ETH_ALEN];
	u16 h_proto;
} STRUCT_PACKED;

/**
 * l2_packet_init - Initialize l2_packet interface
 * @ifname: Interface name
 * @own_addr: Optional own MAC address if available from driver interface or
 *	%NULL if not available
 * @protocol: Ethernet protocol number in host byte order
 * @rx_callback: Callback function that will be called for each received packet
 * @rx_callback_ctx: Callback data (ctx) for calls to rx_callback()
 * @l2_hdr: 1 = include layer 2 header, 0 = do not include header
 * Returns: Pointer to internal data or %NULL on failure
 *
 * rx_callback function will be called with ifindex pointing to the ifindex
 * of the receive interface.  If l2_hdr is set to 0, buf
 * points to len bytes of the payload after the layer 2 header and similarly,
 * TX buffers start with payload. This behavior can be changed by setting
 * l2_hdr=1 to include the layer 2 header in the data buffer.
 */
struct l2_packet_data *l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, int ifindex,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr);

/**
 * l2_packet_deinit - Deinitialize l2_packet interface
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 */
void l2_packet_deinit(struct l2_packet_data *l2);

/**
 * l2_packet_get_own_src_addr - Get own src layer 2 address
 * Checks to see if the port is part of a bond and makes and
 * appropriate selection for the layer 2 src address to use.
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @addr: Buffer for the own address (6 bytes)
 * Returns: 0 on success, -1 on failure
 */
int l2_packet_get_own_src_addr(struct l2_packet_data *l2, u8 *addr);

/**
 * l2_packet_get_own_addr - Get own layer 2 address
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @addr: Buffer for the own address (6 bytes)
 * Returns: 0 on success, -1 on failure
 */
int l2_packet_get_own_addr(struct l2_packet_data *l2, u8 *addr);

void get_remote_peer_mac_addr(struct port *port, struct lldp_agent *);
void l2_packet_get_remote_addr(struct l2_packet_data *l2, u8 *addr);

/**
 * l2_packet_send - Send a packet
 * @l2: Pointer to internal l2_packet data from l2_packet_init()
 * @dst_addr: Destination address for the packet (only used if l2_hdr == 0)
 * @proto: Protocol/ethertype for the packet in host byte order (only used if
 * l2_hdr == 0)
 * @buf: Packet contents to be sent; including layer 2 header if l2_hdr was
 * set to 1 in l2_packet_init() call. Otherwise, only the payload of the packet
 * is included.
 * @len: Length of the buffer (including l2 header only if l2_hdr == 1)
 * Returns: >=0 on success, <0 on failure
 */
int l2_packet_send(struct l2_packet_data *l2, const u8 *dst_addr, u16 proto,
			const u8 *buf, size_t len);

#endif /* L2_PACKET_H */
