/*******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2013

  Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>

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

*******************************************************************************/

/*
 * Definition of the VSI data structure received via netlink interface
 */
#ifndef LLDP_VDPNL_H
#define LLDP_VDPNL_H

#include <linux/if_link.h>
#include <linux/if_ether.h>

#define	MAX_PAYLOAD	4096	/* Maximum Payload Size */

struct vdpnl_mac {		/* MAC-VLAN pair */
	unsigned short vlan;		/* Vlan identifier */
	unsigned char mac[ETH_ALEN];	/* Mac address */
	unsigned char qos;		/* Quality of service */
};

struct vdpnl_vsi {		/* Data structure for VSI data via netlink */
	char ifname[IFNAMSIZ];		/* Interface name */
	int ifindex;			/* Index number */
	unsigned char request;		/* VSI request mode */
	unsigned short response;	/* VSI response code */
	unsigned char vsi_mgrid;
	unsigned char vsi_typeversion;
	unsigned char vsi_uuid[PORT_UUID_MAX];
	unsigned long vsi_typeid;
	unsigned long req_seq;
	pid_t req_pid;
	int macsz;			/* Entries in mac-vlan pair list */
	struct vdpnl_mac *maclist;	/* List of MAC-VLAN pairs */
};

int vdpnl_recv(unsigned char *, size_t);
int vdpnl_send(struct vdpnl_vsi *);
int vdp_request(struct vdpnl_vsi *);
int vdp22_request(struct vdpnl_vsi *);
int vdp_status(int, struct vdpnl_vsi *);
int event_trigger(struct nlmsghdr *, pid_t);
#endif
