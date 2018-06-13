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

#ifndef _LLDP_UTIL_H
#define _LLDP_UTIL_H

#include "lldp.h"
#include "lldp/ports.h"
#include <sys/socket.h>
#include <netinet/in.h>

#define ETHTOOL_GLINK  0x0000000a    /* Get link status (ethtool_value) */

#define max(x,y)  ((x>y)?(x):(y))

/* IETF RFC 4836 dot3MauType: http://tools.ietf.org/rfc/rfc4836.txt */
#define DOT3MAUTYPE_AUI 1
#define DOT3MAUTYPE_10Base5 2
#define DOT3MAUTYPE_Foirl 3
#define DOT3MAUTYPE_10Base2 4
#define DOT3MAUTYPE_10BaseT 5
#define DOT3MAUTYPE_10BaseFP 6
#define DOT3MAUTYPE_10BaseFB 7
#define DOT3MAUTYPE_10BaseFL 8
#define DOT3MAUTYPE_10Broad36 9
#define DOT3MAUTYPE_10BaseTHD 10
#define DOT3MAUTYPE_10BaseTFD 11
#define DOT3MAUTYPE_10BaseFLHD 12
#define DOT3MAUTYPE_10BaseFLFD 13
#define DOT3MAUTYPE_100BaseT4 14
#define DOT3MAUTYPE_100BaseTXHD 15
#define DOT3MAUTYPE_100BaseTXFD 16
#define DOT3MAUTYPE_100BaseFXHD 17
#define DOT3MAUTYPE_100BaseFXFD 18
#define DOT3MAUTYPE_100BaseT2HD 19
#define DOT3MAUTYPE_100BaseT2FD 20
#define DOT3MAUTYPE_1000BaseXHD 21
#define DOT3MAUTYPE_1000BaseXFD 22
#define DOT3MAUTYPE_1000BaseLXHD 23
#define DOT3MAUTYPE_1000BaseLXFD 24
#define DOT3MAUTYPE_1000BaseSXHD 25
#define DOT3MAUTYPE_1000BaseSXFD 26
#define DOT3MAUTYPE_1000BaseCXHD 27
#define DOT3MAUTYPE_1000BaseCXFD 28
#define DOT3MAUTYPE_1000BaseTHD 29
#define DOT3MAUTYPE_1000BaseTFD 30
#define DOT3MAUTYPE_10GBaseX 31
#define DOT3MAUTYPE_10GBaseLX4 32
#define DOT3MAUTYPE_10GBaseR 33
#define DOT3MAUTYPE_10GBaseER 34
#define DOT3MAUTYPE_10GBaseLR 35
#define DOT3MAUTYPE_10GBaseSR 36
#define DOT3MAUTYPE_10GBaseW 37
#define DOT3MAUTYPE_10GBaseEW 38
#define DOT3MAUTYPE_10GBaseLW 39
#define DOT3MAUTYPE_10GBaseSW 40
#define DOT3MAUTYPE_10GBaseCX4 41
#define DOT3MAUTYPE_2BaseTL 42
#define DOT3MAUTYPE_10PassTS 43
#define DOT3MAUTYPE_100BaseBX10D 44
#define DOT3MAUTYPE_100BaseBX10U 45
#define DOT3MAUTYPE_100BaseLX10 46
#define DOT3MAUTYPE_1000BaseBX10D 47
#define DOT3MAUTYPE_1000BaseBX10U 48
#define DOT3MAUTYPE_1000BaseLX10 49
#define DOT3MAUTYPE_1000BasePX10D 50
#define DOT3MAUTYPE_1000BasePX10U 51
#define DOT3MAUTYPE_1000BasePX20D 52
#define DOT3MAUTYPE_1000BasePX20U 53
/* IANA dot3MauType extension */
#define DOT3MAUTYPE_10GBaseT 54
#define DOT3MAUTYPE_10GBaseLRM 55
#define DOT3MAUTYPE_1000BaseKX 56
#define DOT3MAUTYPE_10GBaseKX4 57
#define DOT3MAUTYPE_10GBaseKR 58
#define DOT3MAUTYPE_10_1GBasePRXD1 59
#define DOT3MAUTYPE_10_1GBasePRXD2 60
#define DOT3MAUTYPE_10_1GBasePRXD3 61
#define DOT3MAUTYPE_10_1GBasePRXU1 62
#define DOT3MAUTYPE_10_1GBasePRXU2 63
#define DOT3MAUTYPE_10_1GBasePRXU3 64
#define DOT3MAUTYPE_10GBasePRD1 65
#define DOT3MAUTYPE_10GBasePRD2 66
#define DOT3MAUTYPE_10GBasePRD3 67
#define DOT3MAUTYPE_10GBasePRU1 68
#define DOT3MAUTYPE_10GBasePRU3 69
#define DOT3MAUTYPE_40GBaseKR4 70
#define DOT3MAUTYPE_40GBaseCR4 71
#define DOT3MAUTYPE_40GBaseSR4 72
#define DOT3MAUTYPE_40GBaseFR 73
#define DOT3MAUTYPE_40GBaseLR4 74
#define DOT3MAUTYPE_100GBaseCR10 75
#define DOT3MAUTYPE_100GBaseSR10 76
#define DOT3MAUTYPE_100GBaseLR4 77
#define DOT3MAUTYPE_100GBaseER4 78

int hexstr2bin(const char *hex, u8 *buf, size_t len);
int bin2hexstr(const u8 *hex, size_t hexlen, char *buf, size_t buflen);
int hex2int(char *b);

int is_valid_lldp_device(const char *ifname);
int is_active(const char *ifname);
int is_bond(const char *ifname);
int is_san_mac(u8 *addr);
int is_bridge(const char *ifname);
int is_bridge_port(const char *ifname);
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
int get_ifname(int ifindex, char *ifname);
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
int get_vsistr_arg_count(int ioff, int ilen);

#define ntohll(x) be64_to_cpu(x)
#define htonll(x) cpu_to_be64(x)

#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))

#define hton24(p, v)	do {			\
		p[0] = (((v) >> 16) & 0xFF);	\
		p[1] = (((v) >> 8) & 0xFF);	\
		p[2] = ((v) & 0xFF);		\
	} while (0)


#endif /* _LLDP_UTIL_H */
