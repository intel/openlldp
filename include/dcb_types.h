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

#ifndef _DCB_CLIENT_IF_TYPES_H_
#define _DCB_CLIENT_IF_TYPES_H_

#include <asm/types.h>
#include <stdbool.h>

#define MAX_USER_PRIORITIES       8
#define MAX_BANDWIDTH_GROUPS      8
#define MAX_TRAFFIC_CLASSES       8
#define MIN_TRAFFIC_CLASSES       3
#define SHORT_STRING              20
#define MAX_DESCRIPTION_LEN       100

#define LINK_STRICT_PGID          15

/* DCBX subtypes */
typedef enum {
	dcbx_subtype0 = 0,	/* auto IEEE */
	dcbx_subtype1 = 1,	/* CIN */
	dcbx_subtype2 = 2,	/* CEE */
	dcbx_force_subtype1 = 5,/* FORCE CIN */
	dcbx_force_subtype2 = 6,/* FORCE CEE */
} dcbx_subtype;


#define MASK_DCBX_FORCE 0x03
#define DCBX_FORCE_BIT  0x04

/* PFC configuration */
typedef enum {
	pfc_disabled   = 0x000,
	pfc_enabled,
	pfc_invalid,
} pfc_type;

/* Peer DCB TLV States */
typedef enum {
	DCB_PEER_NONE  = 0x000,
	DCB_PEER_PRESENT,
	DCB_PEER_EXPIRED,
	DCB_PEER_RESET,
} peer_dcb_tlv_state;

typedef pfc_type dcb_pfc_type;

typedef enum {
	dcb_none       = 0x0000,
	dcb_group,
	dcb_link,
	dcb_invalid,
} dcb_strict_priority_type;

typedef pfc_type dcb_pfc_list_type[MAX_USER_PRIORITIES];

typedef struct dcb_user_priority_attribs {
	__u8 pgid;
	__u8 bwgid;
	__u8 percent_of_pg_cap;
	dcb_strict_priority_type   strict_priority;
} dcb_user_priority_attribs_type;

typedef struct dcb_traffic_attribs {
	__u8 pg_percent[MAX_BANDWIDTH_GROUPS]; /* percent of link */
	dcb_user_priority_attribs_type up[MAX_USER_PRIORITIES];
} dcb_traffic_attribs_type;

/* Define protocol and feature version that we support */
#define DCB_MAX_VERSION         0
#define DCB_PG_MAX_VERSION      0
#define DCB_PFC_MAX_VERSION     0
#define DCB_APPTLV_MAX_VERSION  0
#define DCB_LLINK_MAX_VERSION   0

#define DCB_START_SEQ_NUMBER    0

/*  Definitions for dcb protocol event Flags. */
#define DCB_LOCAL_CHANGE_PG      0x00000001U
#define DCB_REMOTE_CHANGE_PG     0x00000002U
#define DCB_LOCAL_CHANGE_PFC     0x00000004U
#define DCB_REMOTE_CHANGE_PFC    0x00000008U
#define DCB_LOCAL_CHANGE_LLINK   0x00000010U
#define DCB_REMOTE_CHANGE_LLINK  0x00000020U
#define DCB_LOCAL_CHANGE_APP     0x00000040U
#define DCB_REMOTE_CHANGE_APP    0x00000080U
#define DCB_EVENT_FLAGS          0x00000FFFU

/*  There are multiple APP event flags, one for each subtype */
#define DCB_EVT_SUB(e, sub)	 ((e) << ((sub)*2))

#define DCB_LOCAL_CHANGE_APPTLV(sub)  ((DCB_LOCAL_CHANGE_APP) << ((sub)*2))
#define DCB_REMOTE_CHANGE_APPTLV(sub) ((DCB_REMOTE_CHANGE_APP) << ((sub)*2))

#define DCB_SET_ALL_FLAGS(t)	({					\
					int i, mask;			\
									\
					mask = DCB_##t##_CHANGE_PG;	\
					mask |= DCB_##t##_CHANGE_PFC;	\
					mask |= DCB_##t##_CHANGE_LLINK;	\
					for (i = 0; i < DCB_MAX_APPTLV; i++) \
					   mask |= DCB_##t##_CHANGE_APPTLV(i);\
					mask;				\
				})

/* DCB SubTypes */
#define DEFAULT_SUBTYPE			0
#define APP_STYPE_LEN			1
#define APP_FCOE_STYPE			0
#define APP_FCOE_STYPE_LEN		1
#define APP_FCOE_DEFAULT_DATA		0x08 /* user priority 3 */
#define APP_ISCSI_STYPE			1
#define APP_ISCSI_STYPE_LEN		1
#define APP_ISCSI_DEFAULT_DATA		0x10
#define APP_FIP_STYPE			2
#define APP_FIP_STYPE_LEN		1
#define APP_FIP_DEFAULT_DATA		0x08 /* no default FIP */

#define DCB_MAX_APPTLV		      3  /* max APP TLV supported */

/* Link SubTypes */

#define LLINK_FCOE_STYPE              0

#define DCB_MAX_LLKTLV		      1  /* max Link TLV supported */

/* Max TLV length */
#define DCB_MAX_TLV_LENGTH          507

/* Definitions for different data store. */
#define LOCAL_STORE                 0x00000001
#define PEER_STORE                  0x00000002
#define OPER_STORE                  0x00000004
#define DATA_STORE_FLAGS            0x0000000F

#define MAX_DEVICE_NAME_LEN         256 /* NDIS supports 256 */
#define MAC_ADDR_LEN                6
#define LLDP_RXPKT_LEN              2300

/* DCB Feature and control states */
#define DCB_NSTATES                 3

#define DCB_CLOSED                  0    /* closed */
#define DCB_INIT                    1    /* Initialization */
#define DCB_LISTEN                  2    /* listening for peer */

/* APP ETH TYPE */
#ifndef APP_FCOE_ETHTYPE
#define APP_FCOE_ETHTYPE 0x8906
#endif

#ifndef APP_FIP_ETHTYPE
#define APP_FIP_ETHTYPE 0x8914
#endif

/* APP PROTOCOL TYPES */
#define APP_ISCSI_PORT 3260

/* Flags */
#define DCB_SET_FLAGS(_FlagsVar, _BitsToSet)    \
		(_FlagsVar) = (_FlagsVar) | (_BitsToSet)

#define DCB_TEST_FLAGS(_FlagsVar, _Mask, _BitsToCheck)    \
		(((_FlagsVar) & (_Mask)) == (_BitsToCheck))

/* Field Error_Flag for feature Oper_state_config */
typedef struct feature_protocol_attribs {
	bool Enable;
	bool Willing;
	bool Advertise;
	bool Advertise_prev;
	bool OperMode;
	bool PeerWilling; 	/* for local data   */
	bool Error;
	bool Syncd;
	__u32 Oper_version;
	__u32 Max_version;
	__u32 FeatureSeqNo;
	bool TLVPresent;   /* for Peer data    */
	bool tlv_sent;     /* for local config */
	bool force_send;   /* for local config */
	__u8 dcbx_st;
	__u16 State;
	__u8 Error_Flag; /* bitmap of Oper and Peer errors */
} feature_protocol_attribs;

typedef struct control_protocol_attribs {
	__u32 Oper_version;
	__u32 Max_version;
	__u32 SeqNo;
	__u32 AckNo;
	__u32 MyAckNo;
	peer_dcb_tlv_state RxDCBTLVState; /* for Peer data */
	__u16 State;
	__u8 Error_Flag; /* bitmap */
} control_protocol_attribs;

typedef struct pg_attribs {
	feature_protocol_attribs protocol;
	dcb_traffic_attribs_type tx;
	dcb_traffic_attribs_type rx;
	__u8 num_tcs;
} pg_attribs;

typedef struct pfc_attribs {
	feature_protocol_attribs    protocol;
	dcb_pfc_list_type      admin;
	__u8 num_tcs;
} pfc_attribs;

typedef char dcb_descript[MAX_DESCRIPTION_LEN];

typedef struct pg_info {
	__u8 max_pgid_desc;
	dcb_descript pgid_desc[MAX_BANDWIDTH_GROUPS];
} pg_info;

typedef struct app_attribs {
	feature_protocol_attribs protocol;
	__u32 Length;
	__u8  AppData[DCB_MAX_TLV_LENGTH];
} app_attribs;

typedef struct llink_cfg {
	__u8 llink_status; 
} llink_cfg;

typedef struct llink_attribs {
	feature_protocol_attribs protocol;
	llink_cfg llink;
} llink_attribs;

typedef struct full_dcb_attribs {
	pg_attribs pg;
	pfc_attribs pfc;
	pg_info descript;
	app_attribs app[DCB_MAX_APPTLV];
	llink_attribs llink[DCB_MAX_LLKTLV];
} full_dcb_attribs;

typedef struct full_dcb_attrib_ptrs {
	pg_attribs *pg;
	pfc_attribs *pfc;
	pg_info *pgid;
	app_attribs *app;
	__u8 app_subtype;
	llink_attribs *llink;
	__u8 llink_subtype;
} full_dcb_attrib_ptrs;

typedef struct feature_support {
	/* non-zero indicates support */
	__u8  pg;         /* priority groups */
	__u8  pfc;        /* priority flow control */

	/* non-zero indicates support */
	__u8  up2tc_mappable; /* abilty to map priorities to traffic classes */
	__u8  gsp;        /* group strict priority */

	/* Each bit represents a number of traffic classes supported by the hw.
	 * If 4 or 8 traffic classes can be configured, then the value is 0x88.
	 */
	__u8  traffic_classes;
	__u8  pfc_traffic_classes;

	__u8  dcbx;
} feature_support;

typedef struct dcbx_state {
	__u32 SeqNo;
	__u32 AckNo;
	bool FCoEenable;
	bool iSCSIenable;
	bool FIPenable;
} dcbx_state;

#endif /* DCB_CLIENT_IF_TYPES_H_ */
