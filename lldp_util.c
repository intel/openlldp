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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netlink/msg.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <linux/sockios.h>
#include <dirent.h>
#include "linux/if_bonding.h"
#include "linux/if_bridge.h"
#include "linux/ethtool.h"
#include "linux/rtnetlink.h"
#include "linux/if_vlan.h"
#include "linux/if.h"
#include "lldp.h"
#include "lldp_util.h"
#include "messages.h"
#include "lldp_dcbx_nl.h"

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * bin2hexstr - Convert binary data to ASCII string
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
#define BYTE2CHAR(b)	(((b) > 9) ? ((b) - 0xa + 'A') : ((b) + '0'))
int bin2hexstr(const u8 *hex, size_t hexlen, char *buf, size_t buflen)
{
	u8 b;
	size_t i, j;

	for (i = j = 0; (i < hexlen) && (j < buflen); i++, j +=2) {
		b = (hex[i] & 0xf0) >> 4;
		buf[j] = BYTE2CHAR(b);
		b = hex[i] & 0x0f;
		buf[j + 1] = BYTE2CHAR(b);
	}
	return 0;
}

/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, u8 *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	u8 *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

/* assumes input is pointer to two hex digits */
/* returns -1 on error */
int hex2int(char *b)
{
	int i;
	int n=0;
	int m;

	for (i=0,m=1; i<2; i++,m--) {
		if (isxdigit(*(b+i))) {
			if (*(b+i) <= '9')
				n |= (*(b+i) & 0x0f) << (4*m);
			else
				n |= ((*(b+i) & 0x0f) + 9) << (4*m);
		}
		else {
			return -1;
		}
	}
	return n;
}

char *print_mac(char *mac, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)*(mac + 0),
		(unsigned char)*(mac + 1),
		(unsigned char)*(mac + 2),
		(unsigned char)*(mac + 3),
		(unsigned char)*(mac + 4),
		(unsigned char)*(mac + 5));
	return buf;
}

static int get_ioctl_socket(void)
{
	static int ioctl_socket = -1;

	if (ioctl_socket >= 0)
		return ioctl_socket;
	ioctl_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_socket < 0) {
		int err = errno;

		perror("socket create failed\n");
		errno = err;
	}
	return ioctl_socket;
}

int is_valid_lldp_device(const char *device_name)
{
	if (is_loopback(device_name))
		return 0;
	if (is_vlan(device_name))
		return 0;
	if (is_bridge(device_name))
		return 0;
	if (is_macvtap(device_name))
		return 0;
	return 1;
}

/**
 *	is_bond - check if interface is a bond interface
 *	@ifname: name of the interface
 *
 *	Returns 0 if ifname is not a bond, 1 if it is a bond.
 */
int is_bond(const char *ifname)
{
	int fd;
	int rc = 0;
	struct ifreq ifr;
	ifbond ifb;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, ifname);
		memset(&ifb, 0, sizeof(ifb));
		ifr.ifr_data = (caddr_t)&ifb;
		if (ioctl(fd, SIOCBONDINFOQUERY, &ifr) == 0)
			rc = 1;
	}
	return rc;
}

/**
 *	get_src_mac_from_bond - select a source MAC to use for slave
 *	@bond_port: pointer to port structure for a bond interface
 *	@ifname: interface name of the slave port
 *	@addr: address of buffer in which to return the selected MAC address
 *
 *	Checks to see if ifname is a slave of the bond port.  If it is,
 *	then a
 *	Returns 0 if a source MAC from the bond could not be found. 1 is
 *	returned if the slave was found in the bond.  addr is updated with
 *	the source MAC that should be used.
*/
int	get_src_mac_from_bond(struct port *bond_port, char *ifname, u8 *addr)
{
	int fd;
	struct ifreq ifr;
	ifbond ifb;
	ifslave ifs;
	char act_ifname[IFNAMSIZ];
	unsigned char bond_mac[ETH_ALEN], san_mac[ETH_ALEN];
	int found = 0;
	int i;

	fd = get_ioctl_socket();
	if (fd < 0)
		return 0;

	memset(bond_mac, 0, sizeof(bond_mac));
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, bond_port->ifname);
	memset(&ifb, 0, sizeof(ifb));
	ifr.ifr_data = (caddr_t)&ifb;
	if (ioctl(fd,SIOCBONDINFOQUERY, &ifr) == 0) {
		/* get the MAC address for the current bond port */
		if (ioctl(fd,SIOCGIFHWADDR, &ifr) == 0)
			memcpy(bond_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		else
			perror("error getting bond MAC address");

		/* scan the bond's slave ports and looking for the
		 * current port and the active slave port.
		*/
		memset(act_ifname, 0, sizeof(act_ifname));
		for (i = 0; i < ifb.num_slaves; i++) {
			memset(&ifs, 0, sizeof(ifs));
			ifs.slave_id = i;
			ifr.ifr_data = (caddr_t)&ifs;

			if (ioctl(fd,SIOCBONDSLAVEINFOQUERY, &ifr) == 0) {
				if (!strncmp(ifs.slave_name, ifname,
					IFNAMSIZ))
					found = 1;

				if (ifs.state == BOND_STATE_ACTIVE)
					strncpy(act_ifname, ifs.slave_name,
						IFNAMSIZ);
			}
		}
	}

	/* current port is not a slave of the bond */
	if (!found)
		return 0;

	/* Get slave port's current perm MAC address
	 * This will be the default return value
	*/
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd,SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	}
	else {
		perror("error getting slave MAC address");
		return 0;
	}

	switch (ifb.bond_mode) {
	case BOND_MODE_ACTIVEBACKUP:
		/* If current port is not the active slave, then
		 * if the bond MAC is equal to the port's
		 * permanent MAC, then find and return
		 * the permanent MAC of the active
		 * slave port. Otherwise, return the
		 * permanent MAC of the port.
		*/
		if (strncmp(ifname, act_ifname, IFNAMSIZ))
			if (get_perm_hwaddr(ifname, addr, san_mac) == 0)
				if (!memcmp(bond_mac, addr, ETH_ALEN))
					get_perm_hwaddr(act_ifname, addr,
								san_mac);
		break;
	default:
		/* Use the current MAC of the port */
		break;
	}

	return 1;
}

/*
 * Return true if the mac address is valid (non-zero and no hardware
 * broadcast address)
 */
int is_valid_mac(const u8 *mac)
{
	static const u8 zero_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	static const u8 ff_mac[ETH_ALEN]   = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	static const u8 iana_mcast[ETH_ALEN] = {0x01, 0x00, 0x5E};
	static const u8 ipv6_mcast[ETH_ALEN] = {0x33, 0x33};

        if(memcmp(mac, zero_mac, ETH_ALEN) == 0 ||
	   memcmp(mac, ff_mac, ETH_ALEN)   == 0)
                return 0;

	/* IANA multicast and ipv6 multicast mac address
	 * For reference check document: 
	 * https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
	 */
        if(memcmp(mac, iana_mcast, 3) == 0 ||
           memcmp(mac, ipv6_mcast, 2) == 0)
                return 0;
	
        return 1;
}

int read_int(const char *path)
{
	int rc = -1;
	char buf[256];
	FILE *f = fopen(path, "r");

	if (f) {
		if (fgets(buf, sizeof(buf), f))
			rc = atoi(buf);
		fclose(f);
	}
	return rc;
}

int read_bool(const char *path)
{
	return read_int(path) > 0;
}

int get_ifflags(const char *ifname)
{
	int fd;
	int flags = 0;
	struct ifreq ifr;

	/* use ioctl */
	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
			flags = ifr.ifr_flags;
	}
	return flags;
}

int get_ifname(int ifindex, char *ifname)
{
	int fd;
	int rc;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	fd = get_ioctl_socket();
	if (fd < 0)
		return -1;

	ifr.ifr_ifindex = ifindex;
	rc = ioctl(fd, SIOCGIFNAME, &ifr);
	if (rc >= 0)
		memcpy(ifname, ifr.ifr_name, IFNAMSIZ);

	return rc;
}

int get_ifpflags(const char *ifname)
{
	int fd;
	int flags = 0;
	struct ifreq ifr;

	/* use ioctl */
	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFPFLAGS, &ifr) == 0)
			flags = ifr.ifr_flags;
	}
	return flags;
}

int get_iftype(const char *ifname)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/class/net/%s/type", ifname);
	return read_int(path);
}

int get_iffeatures(const char *ifname)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/class/net/%s/features", ifname);
	return read_int(path);

}

int get_iflink(const char *ifname)
{
	char path[256];

	snprintf(path, sizeof(path), "/sys/class/net/%s/iflink", ifname);
	return read_int(path);
}

int is_ether(const char *ifname)
{
	/* check for bridge in sysfs */
	int type = get_iftype(ifname);

	return (type == ARPHRD_ETHER) || (type == ARPHRD_EETHER);
}


int is_loopback(const char *ifname)
{
	return get_ifflags(ifname) & IFF_LOOPBACK;
}

int is_p2p(const char *ifname)
{
	return get_ifflags(ifname) & IFF_POINTOPOINT;
}

int is_noarp(const char *ifname)
{
	return get_ifflags(ifname) & IFF_NOARP;
}

int is_mbond(const char *ifname)
{
	return get_ifflags(ifname) & IFF_MASTER;
}

int is_sbond(const char *ifname)
{
	return get_ifflags(ifname) & IFF_SLAVE;
}

int is_slave(const char *ifmaster, const char *ifslave)
{
	int i;
	int rc = 0;
	int fd;
	struct ifreq ifr;
	struct ifbond ifb;
	struct ifslave ifs;

	if (!is_mbond(ifmaster))
		goto out_done;

	fd = get_ioctl_socket();
	if (fd < 0)
		goto out_done;

	memset(&ifr, 0, sizeof(ifr));
	memset(&ifb, 0, sizeof(ifb));
	strncpy(ifr.ifr_name, ifmaster, IFNAMSIZ);
	ifr.ifr_data = (caddr_t)&ifb;
	if (ioctl(fd, SIOCBONDINFOQUERY, &ifr))
		goto out_done;

	for (i = 0; i < ifb.num_slaves; i++) {
		memset(&ifs, 0, sizeof(ifs));
		ifs.slave_id = i;
		ifr.ifr_data = (caddr_t)&ifs;
		if (ioctl(fd, SIOCBONDSLAVEINFOQUERY, &ifr) == 0) {
			if (!strncmp(ifs.slave_name, ifslave, IFNAMSIZ)) {
				rc = 1;
				break;
			}
		}
	}

out_done:
	return rc;
}

int get_ifidx(const char *ifname)
{
	int fd;
	int idx = 0;
	struct ifreq ifreq;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifreq, 0, sizeof(ifreq));
		strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
		if (ioctl(fd, SIOCGIFINDEX, &ifreq) == 0)
			idx = ifreq.ifr_ifindex;
	}
	return idx;
}

int get_master(const char *ifname)
{
	int i;
	int idx = 0;
	int fd;
	int cnt;
	struct ifreq *ifr = NULL;
	struct ifconf ifc;
	char ifcbuf[sizeof(struct ifreq) * 32];

	/* if it's a master bond, return its own index */
	if (is_mbond(ifname))
		return get_ifidx(ifname);

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifc, 0, sizeof(ifc));
		memset(ifcbuf, 0, sizeof(ifcbuf));
		ifc.ifc_buf = ifcbuf;
		ifc.ifc_len = sizeof(ifcbuf);
		if (ioctl(fd, SIOCGIFCONF, (caddr_t)&ifc) == 0) {
			ifr = ifc.ifc_req;
			cnt = ifc.ifc_len/sizeof(struct ifreq);
			for (i = 0; i < cnt; i++, ifr++) {
				if (!strncmp(ifr->ifr_name, ifname, IFNAMSIZ))
					continue;
				if (!is_mbond(ifr->ifr_name))
					continue;
				if (!is_slave(ifr->ifr_name, ifname))
					continue;
				if (ioctl(fd, SIOCGIFINDEX, ifr) == 0)
					idx = ifr->ifr_ifindex;
				break;
			}
		}
	}
	return idx;
}

int is_bridge(const char *ifname)
{
	int fd;
	int rc = 0;
	char path[256];
	DIR *dirp;

	if (!is_ether(ifname)) {
		return 0;
	}
	/* check for bridge in sysfs */
	snprintf(path, sizeof(path), "/sys/class/net/%s/bridge", ifname);
	dirp = opendir(path);
	if (dirp) {
		closedir(dirp);
		rc = 1;
	} else {
		/* use ioctl */
		fd = get_ioctl_socket();
		if (fd >= 0) {
			struct ifreq ifr;
			struct __bridge_info bi;
			unsigned long args[4] = { BRCTL_GET_BRIDGE_INFO,
						 (unsigned long) &bi, 0, 0 };

			ifr.ifr_data = (char *)args;
			strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
			if (ioctl(fd, SIOCDEVPRIVATE, &ifr) == 0)
				rc = 1;
		}
	}
	return rc;
}

int is_bridge_port(const char *ifname)
{
	int rc = 0;
	char path[256];
	DIR *dirp;

	if (!is_ether(ifname)) {
		return 0;
	}
	/* check if the given ifname is a bridge port in sysfs */
	snprintf(path, sizeof(path), "/sys/class/net/%s/brport/", ifname);
	dirp = opendir(path);
	if (dirp) {
		closedir(dirp);
		rc = 1;
	}

	return rc;
}

int is_vlan(const char *ifname)
{
	int fd;
	int rc = 0;
	struct vlan_ioctl_args ifv;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifv, 0, sizeof(ifv));
		ifv.cmd = GET_VLAN_REALDEV_NAME_CMD;
		strncpy(ifv.device1, ifname, sizeof(ifv.device1));
		if (ioctl(fd, SIOCGIFVLAN, &ifv) == 0)
			rc = 1;
	}
	return rc;
}

int is_vlan_capable(const char *ifname)
{

	int features = get_iffeatures(ifname);

	#ifndef NETIF_F_VLAN_CHALLENGED
	#define NETIF_F_VLAN_CHALLENGED 1024
	#endif
	return !(features & NETIF_F_VLAN_CHALLENGED);
}

int is_wlan(const char *ifname)
{
	int fd;
	int rc = 0;
	struct iwreq iwreq;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&iwreq, 0, sizeof(iwreq));
		strncpy(iwreq.ifr_name, ifname, sizeof(iwreq.ifr_name));
		if (ioctl(fd, SIOCGIWNAME, &iwreq) == 0)
			rc = 1;
	}
	return rc;
}

#define NLMSG_SIZE 1024

static struct nla_policy ifla_info_policy[IFLA_INFO_MAX + 1] =
{
  [IFLA_INFO_KIND]       = { .type = NLA_STRING},
  [IFLA_INFO_DATA]       = { .type = NLA_NESTED },
};

int is_macvtap(const char *ifname)
{
	int ret, s;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifinfo;
	struct nlattr *tb[IFLA_MAX+1],
		      *tb2[IFLA_INFO_MAX+1];

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	if (s < 0) {
		goto out;
	}

	nlh = malloc(NLMSG_SIZE);

	if (!nlh) {
		goto out;
	}

	memset(nlh, 0, NLMSG_SIZE);

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        nlh->nlmsg_type = RTM_GETLINK;
        nlh->nlmsg_flags = NLM_F_REQUEST;

	ifinfo = NLMSG_DATA(nlh);
	ifinfo->ifi_family = AF_UNSPEC;
	ifinfo->ifi_index = get_ifidx(ifname);

	ret = send(s, nlh, nlh->nlmsg_len, 0);

	if (ret < 0) {
		goto out_free;
	}

	memset(nlh, 0, NLMSG_SIZE);

	do {
		ret = recv(s, (void *) nlh, NLMSG_SIZE, MSG_DONTWAIT);
	} while ((ret < 0) && errno == EINTR);

	if (nlmsg_parse(nlh, sizeof(struct ifinfomsg),
			(struct nlattr **)&tb, IFLA_MAX, NULL)) {
		goto out_free;
	}

	if (tb[IFLA_IFNAME]) {
		ifname = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	} else {
		ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);
	}

	if (tb[IFLA_LINKINFO]) {
		if (nla_parse_nested(tb2, IFLA_INFO_MAX, tb[IFLA_LINKINFO],
				     ifla_info_policy)) {
			goto out_free;
		}

		if (tb2[IFLA_INFO_KIND]) {
			char *kind = (char*)(RTA_DATA(tb2[IFLA_INFO_KIND]));
			if (!(strcmp("macvtap", kind) && strcmp("macvlan", kind))) {
				free(nlh);
				close(s);
				return true;
			}
		}

	} else {
		goto out_free;
	}

out_free:
	free(nlh);
out:
	close(s);
	return false;
}

static int is_router(void)
{
	int rc = 0;
	char path[256];

	snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/all/forwarding");
	rc = read_bool(path);

	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/all/forwarding");
	rc |= read_bool(path);

	return rc;
}

int is_active(const char *ifname)
{
	int fd;
	int rc = 0;
	struct ifreq ifr;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
			if (ifr.ifr_flags & IFF_UP)
				rc = 1;
	}
	return rc;
}

int is_autoneg_supported(const char *ifname)
{
	int rc = 0;
	int fd;
	struct ifreq ifr;
	struct ethtool_cmd cmd;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd = ETHTOOL_GSET;
		ifr.ifr_data = &cmd;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCETHTOOL, &ifr) == 0)
			if (cmd.supported & SUPPORTED_Autoneg)
				rc = 1;
	}
	return rc;
}

int is_autoneg_enabled(const char *ifname)
{
	int rc = 0;
	int fd;
	struct ifreq ifr;
	struct ethtool_cmd cmd;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd = ETHTOOL_GSET;
		ifr.ifr_data = &cmd;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCETHTOOL, &ifr) == 0)
			rc = cmd.autoneg;
	}
	return rc;
}

/* IETF RFC 3636 dot3MauType: http://www.rfc-editor.org/rfc/rfc3636.txt */
#define MAUCAPADV_bOther	(1 << 0) /* other or unknown */
#define MAUCAPADV_b10baseT	(1 << 1) /* 10BASE-T  half duplex mode */
#define MAUCAPADV_b10baseTFD	(1 << 2) /* 10BASE-T  full duplex mode */
#define MAUCAPADV_b100baseT4	(1 << 3) /* 100BASE-T4 */
#define MAUCAPADV_b100baseTX	(1 << 4) /* 100BASE-TX half duplex mode */
#define MAUCAPADV_b100baseTXFD	(1 << 5) /* 100BASE-TX full duplex mode */
#define MAUCAPADV_b100baseT2	(1 << 6) /* 100BASE-T2 half duplex mode */
#define MAUCAPADV_b100baseT2FD	(1 << 7) /* 100BASE-T2 full duplex mode */
#define MAUCAPADV_bFdxPause	(1 << 8) /* PAUSE for full-duplex links */
#define MAUCAPADV_bFdxAPause	(1 << 9) /* Asymmetric PAUSE for full-duplex links */
#define MAUCAPADV_bFdxSPause	(1 << 10) /* Symmetric PAUSE for full-duplex links */
#define MAUCAPADV_bFdxBPause	(1 << 11) /* Asymmetric and Symmetric PAUSE for full-duplex links */
#define MAUCAPADV_b1000baseX	(1 << 12) /* 1000BASE-X, -LX, -SX, -CX half duplex mode */
#define MAUCAPADV_b1000baseXFD	(1 << 13) /* 1000BASE-X, -LX, -SX, -CX full duplex mode */
#define MAUCAPADV_b1000baseT	(1 << 14) /* 1000BASE-T half duplex mode */
#define MAUCAPADV_b1000baseTFD	(1 << 15) /* 1000BASE-T full duplex mode */
int get_maucaps(const char *ifname)
{
	int fd;
	u16 caps = MAUCAPADV_bOther;
	struct ifreq ifr;
	struct ethtool_cmd cmd;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd = ETHTOOL_GSET;
		ifr.ifr_data = &cmd;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
			if (cmd.advertising & ADVERTISED_10baseT_Half)
				caps |= MAUCAPADV_b10baseT;
			if (cmd.advertising & ADVERTISED_10baseT_Full)
				caps |= MAUCAPADV_b10baseTFD;
			if (cmd.advertising & ADVERTISED_100baseT_Half)
				caps |= MAUCAPADV_b100baseTX;
			if (cmd.advertising & ADVERTISED_100baseT_Full)
				caps |= MAUCAPADV_b100baseTXFD;
			if (cmd.advertising & ADVERTISED_1000baseT_Half)
				caps |= MAUCAPADV_b1000baseT;
			if (cmd.advertising & ADVERTISED_1000baseT_Full)
				caps |= MAUCAPADV_b1000baseTFD;
			if (cmd.advertising & ADVERTISED_Pause)
				caps |= (MAUCAPADV_bFdxPause | MAUCAPADV_bFdxSPause);
			if (cmd.advertising & ADVERTISED_Asym_Pause)
				caps |= MAUCAPADV_bFdxAPause;
			if (cmd.advertising & (ADVERTISED_Asym_Pause | ADVERTISED_Pause))
				caps |= MAUCAPADV_bFdxBPause;
		}
	}
	return caps;
}

int get_mautype(const char *ifname)
{
	int rc = 0;
	int fd;
	struct ifreq ifr;
	struct ethtool_cmd cmd;
	u32 speed;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd = ETHTOOL_GSET;
		ifr.ifr_data = &cmd;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
			/* TODO: too many dot3MauTypes,
			 * should check duplex, speed, and port */
			speed = (cmd.speed_hi << 16) | cmd.speed;
			if (cmd.port == PORT_AUI)
				rc = DOT3MAUTYPE_AUI;
			else if (speed == SPEED_10)
				rc = DOT3MAUTYPE_10BaseT;
			else if (speed == SPEED_100)
				rc = DOT3MAUTYPE_100BaseTXFD;
			else if (speed == SPEED_1000)
				rc = DOT3MAUTYPE_1000BaseTFD;
		}
	}
	return rc;
}

int get_mtu(const char *ifname)
{
	int fd;
	int rc = 0;
	struct ifreq ifr;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
			rc = ifr.ifr_mtu;
	}
	return rc;
}

int get_mfs(const char *ifname)
{
	int mfs = get_mtu(ifname);

	#ifndef VLAN_HLEN
	#define VLAN_HLEN	4
	#endif
	if (mfs) {
		mfs += ETH_HLEN + ETH_FCS_LEN;
		if (is_vlan_capable(ifname))
			mfs += VLAN_HLEN;
	}
	return mfs;
}

int get_mac(const char *ifname, u8 mac[])
{
	int fd;
	int rc = EINVAL;
	struct ifreq ifr;

	memset(mac, 0, 6);
	fd = get_ioctl_socket();
	if (fd >= 0) {
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (!ioctl(fd, SIOCGIFHWADDR, &ifr)) {
			memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
			rc = 0;
		}
	}
	return rc;
}

int get_macstr(const char *ifname, char *addr, size_t size)
{
	u8 mac[6];
	int rc;

	rc = get_mac(ifname, mac);
	if (rc == 0) {
		snprintf(addr, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1],	mac[2],	mac[3],	mac[4],	mac[5]);
	}
	return rc;
}


u16 get_caps(const char *ifname)
{
	u16 caps = 0;

	/* how to find TPID to determine C-VLAN vs. S-VLAN ? */
	if (is_vlan(ifname))
		caps |= SYSCAP_CVLAN;

	if (is_bridge_port(ifname))
		caps |= SYSCAP_BRIDGE;

	if (is_router())
		caps |= SYSCAP_ROUTER;

	if (is_wlan(ifname))
		caps |= SYSCAP_WLAN;
#if 0
	if (is_phone(ifname))
		caps |= SYSCAP_PHONE;
	if (is_docsis(ifname))
		caps |= SYSCAP_DOCSIS;
	if (is_repeater(ifname))
		caps |= SYSCAP_REPEATER;
	if (is_tpmr(ifname))
		caps |= SYSCAP_TPMR;
	if (is_other(ifname))
		caps |= SYSCAP_OTHER;

#endif
	if (!caps)
		caps = SYSCAP_STATION;

	return caps;
}

int get_saddr(const char *ifname, struct sockaddr_in *saddr)
{
	int fd;
	int rc = EIO;
	struct ifreq ifr;

	fd = get_ioctl_socket();
	if (fd >= 0) {
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			memcpy(saddr, &ifr.ifr_addr, sizeof(*saddr));
			rc = 0;
		}
	}
	return rc;
}

int get_ipaddr(const char *ifname, struct in_addr *in)
{
	int rc;
	struct sockaddr_in sa;

	rc = get_saddr(ifname, &sa);
	if (rc == 0)
		memcpy(in, &sa.sin_addr, sizeof(struct in_addr));
	return rc;
}

int get_ipaddrstr(const char *ifname, char *ipaddr, size_t size)
{
	int rc;
	struct sockaddr_in sa;

	rc = get_saddr(ifname, &sa);
	if (rc == 0) {
		memset(ipaddr, 0, size);
		strncpy(ipaddr, inet_ntoa(sa.sin_addr), size);
	}
	return rc;
}

int get_saddr6(const char *ifname, struct sockaddr_in6 *saddr)
{
	int rc = 0;
	struct ifaddrs *ifa;
	struct ifaddrs *ifaddr;

	rc = getifaddrs(&ifaddr);
	if (rc == 0) {
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if ((ifa->ifa_addr->sa_family == AF_INET6) &&
			    (strncmp(ifa->ifa_name, ifname, IFNAMSIZ) == 0)) {
				memcpy(saddr, ifa->ifa_addr, sizeof(*saddr));
				rc = 0;
				break;
			}
		}
	}
	freeifaddrs(ifaddr);
	return rc;
}

int get_ipaddr6(const char *ifname, struct in6_addr *in6)
{
	int rc;
	struct sockaddr_in6 sa;

	rc = get_saddr6(ifname, &sa);
	if (rc == 0)
		memcpy(in6, &sa.sin6_addr, sizeof(struct in6_addr));
	return rc;
}

int get_ipaddr6str(const char *ifname, char *ip, size_t size)
{
	#define ifa_sia(i, f) (((f) == AF_INET) ? \
		 ((void *) &((struct sockaddr_in *) (i))->sin_addr) : \
		 ((void *) &((struct sockaddr_in6 *) (i))->sin6_addr))

	#define ifa_sin(i) \
		 ((void *) &((struct sockaddr_in *) (i)->ifa_addr)->sin_addr)

	#define ifa_sin6(i) \
		 (&((struct sockaddr_in6 *) (i)->ifa_addr)->sin6_addr)

	int rc = 0;
	struct sockaddr_in6 sa;

	rc = get_saddr6(ifname, &sa);
	if (rc == 0)
		if (inet_ntop(sa.sin6_family, &sa.sin6_addr, ip, size) == NULL)
			rc = EIO;
	return rc;
}

int get_addr(const char *ifname, int domain, void *buf)
{
	if (domain == AF_INET)
		return get_ipaddr(ifname, (struct in_addr *)buf);
	else if (domain == AF_INET6)
		return get_ipaddr6(ifname, (struct in6_addr *)buf);
	else if (domain == AF_UNSPEC)
		return get_mac(ifname, (u8 *)buf);
	else
		return -1;
}

/* MAC_ADDR_STRLEN = strlen("00:11:22:33:44:55") */
#define MAC_ADDR_STRLEN	17
int mac2str(const u8 *mac, char *dst, size_t size)
{
	if (dst && size > MAC_ADDR_STRLEN) {
		snprintf(dst, size, "%02X:%02X:%02X:%02X:%02X:%02X",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return 0;
	}
	return -1;
}

int str2mac(const char *src, u8 *mac, size_t size)
{
	int i = 0;
	int rc = -1;

	if (size < 6)
		goto out_err;

	if (!src)
		goto out_err;

	if (strlen(src) != MAC_ADDR_STRLEN)
		goto out_err;

	memset(mac, 0, size);
	for (i = 0; i < 6; i++, mac++)
		if (1 != sscanf(&src[i * 3], "%02hhX", mac))
			goto out_err;
	rc = 0;
out_err:
	return rc;
}

int str2addr(int domain, const char *src, void *dst, size_t size)
{
	if ((domain == AF_INET) || (domain == AF_INET6)) {
		if (1 == inet_pton(domain, src, dst))
			return 0;
		else
			return -1;
	}

	if (domain == AF_UNSPEC)
		return str2mac(src, (u8 *)dst, size);

	return -1;
}

int addr2str(int domain, const void *src, char *dst, size_t size)
{
	if ((domain == AF_INET) || (domain == AF_INET6)) {
		if (inet_ntop(domain, src, dst, size))
			return 0;
		else
			return -1;
	}

	if (domain == AF_UNSPEC)
		return mac2str((u8 *)src, dst, size);

	return -1;
}

/*
 * check_link_status - check the link status of the port
 * @ifname: the port name
 *
 * Returns: 0 if error or no link and non-zero if interface has link
 */
int check_link_status(const char *ifname)
{
	int fd;
	struct ifreq ifr;
	int retval = 0;
	struct link_value
	{
		u32 cmd ;
		u32 data;
	} linkstatus = { ETHTOOL_GLINK, 0};

	fd = get_ioctl_socket();
	if (fd < 0)
		return retval;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_data = (caddr_t)&linkstatus;
	if (ioctl(fd,SIOCETHTOOL, &ifr) == 0)
		retval = linkstatus.data;

	return retval;
}

#define NUM_ARGS 8

int get_arg_val_list(char *ibuf, int ilen, int *ioff,
			    char **args, char **argvals)
{
	u8 arglen = 0;
	u16 argvalue_len;
	int *arglens = NULL;
	int *argvallens = NULL;
	int *p;
	int numargs;
	int i;

	/* parse out args and argvals */
	for (i = 0; ilen - *ioff > 2 * (int)sizeof(arglen); i++) {
		if (!(i % NUM_ARGS)) {
			p = (int *) realloc(arglens,
				(i/NUM_ARGS + 1) * NUM_ARGS * sizeof(int));
			if (!p) {
				free(arglens);
				return 0;
			} else {
				arglens = p;
			}
			p = (int *) realloc(argvallens,
				(i/NUM_ARGS + 1) * NUM_ARGS * sizeof(int));
			if (!p) {
				free(argvallens);
				return 0;
			} else {
				argvallens = p;
			}
		}
		hexstr2bin(ibuf+*ioff, &arglen, sizeof(arglen));
		*ioff += 2 * (int)sizeof(arglen);
		if (ilen - *ioff >= 0) {
			args[i] = ibuf+*ioff;
			*ioff += arglen;
			*(arglens+i) = arglen;

			if (ilen - *ioff >= 2 * (int)sizeof(argvalue_len)) {
				hexstr2bin(ibuf+*ioff, (u8 *)&argvalue_len,
					   sizeof(argvalue_len));
				argvalue_len = ntohs(argvalue_len);
				*ioff += 2*sizeof(argvalue_len);
				if (ilen - *ioff >= 0) {
					argvals[i] = ibuf+*ioff;
					*ioff += argvalue_len;
					*(argvallens+i) = argvalue_len;
				}
			} else {
				free(arglens);
				free(argvallens);
				return 0;
			}
		} else {
			free(arglens);
			free(argvallens);
			return 0;
		}
	}
	numargs = i;
	for (i = 0; i < numargs; i++) {
		args[i][*(arglens+i)] = '\0';
		argvals[i][*(argvallens+i)] = '\0';
	}
	free(arglens);
	free(argvallens);
	return numargs;
}

int get_arg_list(char *ibuf, int ilen, int *ioff, char **args)
{
	u8 arglen = 0;
	int *arglens = NULL;
	int *p;
	int numargs;
	int i;

	/* parse out args */
	for (i = 0; (ilen - *ioff > 2 * (int)sizeof(arglen)); i++) {
		if (!(i % NUM_ARGS)) {
			p = (int *) realloc(arglens,
				(i/NUM_ARGS + 1) * NUM_ARGS * sizeof(int));
			if (!p) {
				free(arglens);
				return 0;
			} else {
				arglens = p;
			}
		}
		hexstr2bin(ibuf+(*ioff), &arglen, sizeof(arglen));
		*ioff += 2*sizeof(arglen);
		if (ilen - *ioff >= arglen) {
			args[i] = ibuf+(*ioff);
			*ioff += arglen;
			*(arglens+i) = arglen;
		} else {
			free(arglens);
			return 0;
		}
	}
	numargs = i;

	for (i = 0; i < numargs; i++)
		args[i][*(arglens+i)] = '\0';

	free(arglens);
	return numargs;
}

/*
 * This functionality can be seen in many places to convert a LenData to a
 * argument array.
 */

int get_vsistr_arg_count(int ioff, int ilen)
{
	int offset;
	int numargs;

	offset = ioff;
	for (numargs = 0; (ilen - offset) > 2; numargs++) {
		offset += 2;
		if (ilen - offset > 0) {
			offset++;
			if (ilen - offset > 4)
				offset += 4;
		}
	}
	return numargs;
}
