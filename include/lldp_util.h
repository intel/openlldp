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

#ifndef _LLDP_UTIL_H
#define _LLDP_UTIL_H

#include "lldp.h"
#include "lldp/ports.h"
#include <sys/socket.h>
#include <netinet/in.h>

#define ETHTOOL_GLINK  0x0000000a    /* Get link status (ethtool_value) */

#define max(x,y)  ((x>y)?(x):(y))

int hexstr2bin(const char *hex, u8 *buf, size_t len);
int bin2hexstr(const u8 *hex, size_t hexlen, char *buf, size_t buflen);

int is_valid_lldp_device(const char *ifname);
int is_active(const char *ifname);
int is_bond(const char *ifname);
int is_san_mac(u8 *addr);
int is_bridge(const char *ifname);
int is_vlan(const char *ifname);
int is_vlan_capable(const char *ifname);
int is_wlan(const char *ifname);
int is_macvtap(const char *ifname);
int is_valid_mac(const u8 *mac);
int is_san_mac(u8 *addr);
int is_ether(const char *ifname);
int is_loopback(const char *ifname);
int is_p2p(const char *ifname);
int is_noarp(const char *ifname);
int is_mbond(const char *ifname);
int is_sbond(const char *ifname);
int is_autoneg_enabled(const char *ifname);
int is_autoneg_supported(const char *ifname);
int get_mtu(const char *);
int get_mfs(const char *);
int get_ifflags(const char *);
int get_maucaps(const char *);
int get_mautype(const char *);
int get_ifpflags(const char *);
int get_iftype(const char *);
int get_src_mac_from_bond(struct port *bond_port, char *ifname, u8 *addr);
int get_mac(const char *ifname, u8 mac[]);
int get_macstr(const char *ifname, char *addr, size_t size);
int get_saddr(const char *ifname, struct sockaddr_in *saddr);
int get_ipaddr(const char *ifname, struct in_addr *);
int get_ipaddrstr(const char *ifname, char *ipaddr, size_t size);
int get_saddr6(const char *ifname, struct sockaddr_in6 *saddr);
int get_ipaddr6(const char *ifname, struct in6_addr *);
int get_ipaddr6str(const char *ifname, char *ipaddr, size_t size);
u16 get_caps(const char *ifname);
int mac2str(const u8 *mac, char *dst, size_t size);
int str2mac(const char *src, u8 *mac, size_t size);
int str2addr(int domain, const char *src, void *dst, size_t size);
int addr2str(int domain, const void *src, char *dst, size_t size);
int is_slave(const char *ifmaster, const char *ifslave);
int get_ifidx(const char *ifname);
int get_master(const char *ifname);
int get_addr(const char *ifname, int domain, void *buf);
int check_link_status(const char *ifname);

int get_arg_val_list(char *ibuf, int ilen, int *ioff,
			    char **args, char **argvals);
int get_arg_list(char *ibuf, int ilen, int *ioff, char **args);

#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))

#define hton24(p, v)	do {			\
		p[0] = (((v) >> 16) & 0xFF);	\
		p[1] = (((v) >> 8) & 0xFF);	\
		p[2] = ((v) & 0xFF);		\
	} while (0)


#endif /* _LLDP_UTIL_H */
