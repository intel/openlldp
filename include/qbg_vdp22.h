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
 * External interface definition for the ratified standard VDP protocol.
 */
#ifndef QBG_VDP22_H
#define QBG_VDP22_H

#include	<sys/queue.h>
#include	<linux/if_ether.h>
#include	<linux/if_link.h>

/*
 * Define VDP22 filter formats.
 */
enum vdp22_ffmt {
	 VDP22_FFMT_VID = 1,
	 VDP22_FFMT_MACVID,
	 VDP22_FFMT_GROUPVIDC,
	 VDP22_FFMT_GROUPMACVID
};

/*
 * Define VDP22 VSI Profile modes.
 */
enum vdp22_modes {
	VDP22_PREASSOC = 1,
	VDP22_PREASSOC_WITH_RR,
	VDP22_ASSOC,
	VDP22_DEASSOC,
	VDP22_MGRID,
	VDP22_OUI = 0x7f
};

enum vdp22_cmdresp {		/* VDP22 Protocol command responses */
	VDP22_RESP_NONE = 255	/* No response returned so far */
};

struct vdp22_mac_vlan {		/* MAC,VLAN entry anchored by profiles */
	unsigned char mac[ETH_ALEN];
	unsigned short vlan;
	unsigned char qos;		/* QOS field */
	pid_t req_pid;			/* PID of requester for profile */
	unsigned long req_seq;		/* Seq # of requester for profile */
	LIST_ENTRY(vdp22_mac_vlan) node;
};

struct vsi22_profile {		/* Profile data */
	char ifname[IFNAMSIZ + 1];	/* Interface name */
	unsigned char req_mode;		/* VSI profile association command */
	unsigned char req_response;	/* Response from switch */
	unsigned char mgrid;		/* Profile mgr id */
	unsigned char typeid_ver;	/* Profile type id version */
	unsigned int typeid;		/* Profile id */
	unsigned char uuid[PORT_UUID_MAX];	/* Profile UUID */
	unsigned char format;		/* Format of MAC,VLAN list */
	unsigned short entries;		/* Number of MAC,VLAN entries in */
					/* macvid_head */
	LIST_HEAD(macvid22_head, vdp22_mac_vlan) macvid_head;
	LIST_ENTRY(vsi22_profile) prof22_node;
	struct vdp22smi *smi;		/* Pointer to state machine info */
	int done;			/* Timer for profile completion */
};

/* Show last char of UUID in trace */
#define	PUMLAST		(PORT_UUID_MAX - 1)

struct vdp22 {		/* Per interface VSI/VDP data */
	char ifname[IFNAMSIZ + 1];	/* Interface name */
	unsigned long long wdly_us;	/* Waitdelay timeout in micro secs */
	unsigned long long ka_us;	/* Keep alive timeout in micro secs */
	unsigned long long resp_us;	/* Response timeout in micro secs */
	unsigned char gpid;		/* Supports group ids in VDP */
	unsigned short input_len;	/* Length of input data from ECP */
	unsigned char input[ETH_DATA_LEN];	/* Input data from ECP */
	LIST_HEAD(profile22_head, vsi22_profile) prof22_head;
	LIST_ENTRY(vdp22) entry;
};

struct vdp22_user_data {		/* Head for all VDP data */
	LIST_HEAD(vdp22_head, vdp22) head;
};

struct lldp_module *vdp22_register(void);
void vdp22_unregister(struct lldp_module *);
void vdp22_start(const char *);
void vdp22_stop(char *);
int vdp22_query(const char *);
int vdp22_addreq(struct vsi22_profile *, struct vdp22 *);

#endif
