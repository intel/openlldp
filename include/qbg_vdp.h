/*******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>
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

#ifndef QBG_VDP_H
#define QBG_VDP_H

#include "lldp_mod.h"
#include "qbg_ecp.h"

#define LLDP_MOD_VDP		(OUI_IEEE_8021Qbg + 1)

#define VDP_MODE_PREASSOCIATE		0x0
#define VDP_MODE_PREASSOCIATE_WITH_RR	0x1
#define VDP_MODE_ASSOCIATE		0x2
#define VDP_MODE_DEASSOCIATE		0x3

#define VDP_RESPONSE_SUCCESS		0x0
#define VDP_RESPONSE_INVALID_FORMAT	0x1
#define VDP_RESPONSE_INSUFF_RESOURCES	0x2
#define VDP_RESPONSE_UNUSED_VTID	0x3
#define VDP_RESPONSE_VTID_VIOLATION	0x4
#define VDP_RESPONSE_VTID_VER_VIOLATION	0x5
#define VDP_RESPONSE_OUT_OF_SYNC	0x6
#define VDP_RESPONSE_UNKNOWN		0xfe
#define VDP_RESPONSE_NO_RESPONSE	0xff

extern const char * const vsi_states[];

#define VDP_FILTER_INFO_FORMAT_VID		0x1
#define VDP_FILTER_INFO_FORMAT_MACVID		0x2
#define VDP_FILTER_INFO_FORMAT_GROUPVID		0x3
#define VDP_FILTER_INFO_FORMAT_GROUPMACVID	0x4

#define VDP_TIMER_GRANULARITY		(100 * MSECS)	/* 100 ms */
#define VDP_KEEPALIVE_TIMER_DEFAULT	(10 * SECS)	/* 10s */
#define VDP_ACK_TIMER_DEFAULT		(2 * ECP_ACK_TIMER_DEFAULT * ECP_MAX_RETRIES)
#define VDP_KEEPALIVE_TIMER_STOPPED	(-1)
#define VDP_ACK_TIMER_STOPPED		(-1)
#define VDP_LOCALCHANGE_TIMEOUT		(1 * MSECS)	/* 1 ms */

#define VDP_ROLE_STATION		0
#define VDP_ROLE_BRIDGE			1

enum {
	VSI_UNASSOCIATED = 0,
	VSI_ASSOC_PROCESSING,
	VSI_ASSOCIATED,
	VSI_PREASSOC_PROCESSING,
	VSI_PREASSOCIATED,
	VSI_DEASSOC_PROCESSING,
	VSI_EXIT,
};

struct mac_vlan_p {
	u8 mac[6];
	u16 vlan;
} __attribute__ ((__packed__));

struct mac_vlan {		/* MAC,VLAN entry anchored by profiles */
	u8 mac[6];
	u16 vlan;
	u8 qos;			/* QOS field */
	pid_t req_pid;		/* PID of requester for this profile */
	u32 req_seq;		/* Seq # of requester for this profile */
	LIST_ENTRY(mac_vlan) entry;
};

struct tlv_info_vdp {		/* VSI information in packet format */
	u8 oui[3];
	u8 sub;
	u8 mode;
	u8 response;
	u8 mgrid;
	u8 id[3];
	u8 version;
	u8 instance[16];
	u8 format;
	u16 entries;
} __attribute__ ((__packed__));

struct vsi_profile {
	int mode;		/* VSI profile association command */
	int response;		/* Response from switch */
	u8 no_nlmsg;		/* Don't send netlink msg on VSI_EXIT */
	u8 mgrid;		/* Profile mgr id */
	int id;			/* Profile id */
	u8 version;		/* Profile id version number */
	u8 instance[16];	/* Profile UUID */
	u8 format;		/* Format of MAC,VLAN list */
	u16 entries;		/* Number of MAC,VLAN entries in macvid_head */
	LIST_HEAD(macvid_head, mac_vlan) macvid_head;
	struct port *port;
	int ackTimer;		/* VDP ACK timer interval */
	int ackReceived;	/* VDP ACK received for this profile */
	int keepaliveTimer;	/* VDP keepalive timer interval */
	int state;		/* State of VDP state machine for profile */
	int seqnr;		/* Seqnr of ECP packet this profile was sent */
	bool localChange;	/* True when state needs change */
	bool remoteChange;	/* True when switch caused profile change */
	bool txmit;		/* Profile transmitted */
	LIST_ENTRY(vsi_profile) profile;
};

struct vdp_data {
	char ifname[IFNAMSIZ];
	u8 enabletx;
	u8 vdpbit_on;		/* Enable VDP Protocol */
	struct ecp ecp;
	struct unpacked_tlv *vdp;
	int role;
	int keepaliveTimer;
	int ackTimer;
	int nroftimers;
	LIST_HEAD(profile_head, vsi_profile) profile_head;
	LIST_ENTRY(vdp_data) entry;
};

struct vdp_user_data {
	LIST_HEAD(vdp_head, vdp_data) head;
};

struct lldp_module *vdp_register(void);
void vdp_unregister(struct lldp_module *);
struct vdp_data *vdp_data(char *);
struct packed_tlv *vdp_gettlv(struct vdp_data *, struct vsi_profile *);
void vdp_vsi_sm_station(struct vsi_profile *);
struct vsi_profile *vdp_add_profile(struct vdp_data *, struct vsi_profile *);
int vdp_remove_profile(struct vsi_profile *);
void vdp_somethingChangedLocal(struct vsi_profile *, bool);
void vdp_update(char *, u8);
void vdp_ifup(char *, struct lldp_agent *);
void vdp_ifdown(char *, struct lldp_agent *);

void vdp_ack_profiles(struct vdp_data *, int);
void vdp_advance_sm(struct vdp_data *);
int vdp_indicate(struct vdp_data *, struct unpacked_tlv *);
int vdp_vsis_pending(struct vdp_data *);
int vdp_vsis(char *);
const char *vdp_response2str(int);
void vdp_trace_profile(struct vsi_profile *);
struct vsi_profile *vdp_alloc_profile(void);
void vdp_delete_profile(struct vsi_profile *);
struct vsi_profile *vdp_find_profile(struct vdp_data *, struct vsi_profile *);

#define MAC_ADDR_STRLEN		18

#endif /* _LLDP_VDP_H */
