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

#ifndef _TLV_DCBX_H_
#define _TLV_DCBX_H_

#include "lldp.h"
#include "dcb_types.h"
#include "lldp_dcbx.h"

/* Received TLV types */
#define RCVD_LLDP_DCBX1_TLV         0x0200
#define RCVD_LLDP_DCBX2_TLV         0x0400

#define RCVD_DCBX1_TLV_CTRL         0x0001
#define RCVD_DCBX2_TLV_CTRL         0x0002
#define RCVD_DCBX_TLV_PG            0x0004
#define RCVD_DCBX_TLV_PFC           0x0008
#define RCVD_DCBX_TLV_APP           0x0020
#define RCVD_DCBX_TLV_LLINK         0x0040

/* DCB TLV Definitions */
#define DCB_CONTROL_TLV                1
#define DCB_PRIORITY_GROUPS_TLV        2
#define DCB_PRIORITY_FLOW_CONTROL_TLV  3
#define DCB_BCN_TLV                    4
#define DCB_APPLICATION_TLV            5
#define DCB_LLINK_TLV                  6

#define DCB_CONTROL_TLV2               1
#define DCB_PRIORITY_GROUPS_TLV2       2
#define DCB_PRIORITY_FLOW_CONTROL_TLV2 3
#define DCB_APPLICATION_TLV2           4

/* DCBX CTRL TLV byte offsets */
#define DCBX_CTRL_OPER_VER_OFFSET   0
#define DCBX_CTRL_MAX_VER_OFFSET    (DCBX_CTRL_OPER_VER_OFFSET + sizeof(u8))
#define DCBX_CTRL_SEQNO_OFFSET      (DCBX_CTRL_MAX_VER_OFFSET + sizeof(u8))
#define DCBX_CTRL_ACKNO_OFFSET      (DCBX_CTRL_SEQNO_OFFSET + sizeof(u32))
#define DCBX_CTRL_LEN               sizeof(struct dcb_control_info)

struct dcbx_tlv_header {
	u8 oper_version;
	u8 max_version;
	u8 ewe;
	u8 sub_type;
};

/* DCBX TLV HEADER byte offsets */
#define DCBX_HDR_OPER_VERSION_OFFSET    0
#define DCBX_HDR_MAX_VERSION_OFFSET     1
#define DCBX_HDR_EWE_OFFSET             2
#define DCBX_HDR_SUB_TYPE_OFFSET        3

#define DCB_PGID_BYTES                  MAX_BANDWIDTH_GROUPS/2

#pragma pack(1) /*packon*/
struct dcbx1_pg_cfg {
	u8 pg_percent[MAX_BANDWIDTH_GROUPS];/* % of link BW per BWG */
	struct {
		u8  byte1;
			/* :3 BWG ID */
			/* :2 strict_prio 2 (1: LSP, 2: GSP, 3: reserved */
			/* :3 padding */
		u8  byte2;                /* percentage of BWG bandwidth */
	} up_cfg[MAX_USER_PRIORITIES];/* Index is user priority */
};
struct dcbx2_pg_cfg {
	u8 pg_ids[DCB_PGID_BYTES];
	/* byte 0 :4 PG ID for UP 0 */
	/*        :4 PG ID for UP 1 */ 
	/* byte 1 :4 PG ID for UP 2 */
	/*        :4 PG ID for UP 3 */ 
	/* byte 2 :4 PG ID for UP 4 */
	/*        :4 PG ID for UP 5 */ 
	/* byte 3 :4 PG ID for UP 6 */
	/*        :4 PG ID for UP 7 */ 
	u8 pg_percent[MAX_BANDWIDTH_GROUPS];/* % of link BW per PGID */
	u8 num_tcs; 
};
#pragma pack() /*packoff*/
/* DCBX PG TLV byte offsets */
#define DCBX1_PG_PERCENT_OFFSET     sizeof(struct dcbx_tlv_header)
#define DCBX1_PG_SETTINGS_OFFSET    (DCBX1_PG_PERCENT_OFFSET + \
				 sizeof(u8)*MAX_BANDWIDTH_GROUPS)
#define BYTE1_OFFSET                 0
#define BYTE2_OFFSET                 1

#define DCBX2_PG_PGID_UP            sizeof(struct dcbx_tlv_header)
#define DCBX2_PG_PERCENT_OFFSET     (DCBX2_PG_PGID_UP + \
					sizeof(u8)*DCB_PGID_BYTES)
#define DCBX2_PG_NUM_TC_OFFSET      (DCBX2_PG_PERCENT_OFFSET + \
					sizeof(u8)*MAX_BANDWIDTH_GROUPS)

#pragma pack(1) /*packon*/
struct dcbx1_pfc_cfg {
	u8 admin_map; /* bitmap of admin mode, bit position is user priority */
};
struct dcbx2_pfc_cfg {
	u8 admin_map; /* bitmap of admin mode, bit position is user priority */
	u8 num_tcs; 
};
#pragma pack() /*packoff*/

/* DCBX PFC TLV byte offsets */
#define DCBX_PFC_MAP_OFFSET            sizeof(struct dcbx_tlv_header)
#define DCBX2_PFC__NUM_TC_OFFSET      (DCBX_PFC_MAP_OFFSET + sizeof(u8))

#pragma pack(1) /*packon*/
struct dcbx2_app_cfg {
	u16 prot_id;
	u8  byte1;
		/* :6 high 7 bits of OUI */
		/* :2 selector field */
	u16 low_oui; /* low 16 bits of OUI */
	u8  up_map;
};
#pragma pack() /*packoff*/
/* DCBX APP TLV byte offsets */
#define DCBX1_APP_DATA_OFFSET          sizeof(struct dcbx_tlv_header)
#define DCBX2_APP_DATA_OFFSET          sizeof(struct dcbx_tlv_header)
/* To support looping, these do *not* include the header */
#define DCBX2_APP_PROTO_OFFSET         0
#define DCBX2_APP_BYTE1_OFFSET         (DCBX2_APP_PROTO_OFFSET + sizeof(u16))
#define DCBX2_APP_LOW_OUI_OFFSET1      (DCBX2_APP_BYTE1_OFFSET + sizeof(u8))
#define DCBX2_APP_LOW_OUI_OFFSET2      (DCBX2_APP_LOW_OUI_OFFSET1 + sizeof(u8))
#define DCBX2_APP_UP_MAP_OFFSET        (DCBX2_APP_LOW_OUI_OFFSET2 + sizeof(u8))

#pragma pack(1) /*packon*/
struct dcbx1_pg_info {
	struct dcbx_tlv_header hdr;
	struct dcbx1_pg_cfg data;
};
struct dcbx2_pg_info {
	struct dcbx_tlv_header hdr;
	struct dcbx2_pg_cfg data;
};
#pragma pack() /*packoff*/
#define DCBX1_PG_LEN                    sizeof(struct dcbx1_pg_info)
#define DCBX2_PG_LEN                    sizeof(struct dcbx2_pg_info)

#pragma pack(1) /*packon*/
struct dcbx1_pfc_info {
	struct dcbx_tlv_header hdr;
	struct dcbx1_pfc_cfg data;
};
struct dcbx2_pfc_info {
	struct dcbx_tlv_header hdr;
	struct dcbx2_pfc_cfg data;
};
#pragma pack() /*packoff*/
#define DCBX1_PFC_LEN                  sizeof(struct dcbx1_pfc_info)
#define DCBX2_PFC_LEN                  sizeof(struct dcbx2_pfc_info)

#pragma pack(1) /*packon*/
struct dcbx1_app_info {
	struct dcbx_tlv_header hdr;
	u8 data[];
};
struct dcbx2_app_info {
	struct dcbx_tlv_header hdr;
	struct dcbx2_app_cfg data[];
};
#pragma pack() /*packoff*/
#define DCBX1_APP_LEN	DCBX1_APP_DATA_OFFSET
#define DCBX2_APP_SIZE	sizeof(struct dcbx2_app_cfg)
#define DCBX2_APP_LEN	(sizeof(struct dcbx2_app_info))

#pragma pack(1) /*packon*/
struct dcbx_llink_cfg {
	u8 byte1; /* :1 - logical link status */
};            /* :7 - reserved */
#pragma pack() /*packoff*/

/* DCB_TLV TYPE 6 byte offset */
#define DCBX_LLINK_STATUS_OFFSET       sizeof(struct dcbx_tlv_header)

#pragma pack(1) /*packon*/
struct dcbx_llink_info {
	struct dcbx_tlv_header hdr;
	struct dcbx_llink_cfg data;
};
#pragma pack() /*packoff*/
#define DCBX_LLINK_LEN                 sizeof(struct dcbx_llink_info)

/* Organizationally Unique Identifier */
#define DCB_OUI_LEN     3
#define OUI_SUBTYPE_LEN 1

struct dcb_tlv {
	u8 oui[DCB_OUI_LEN];
	u8 oui_subtype;
};

#pragma pack(1) /*packon*/
struct dcb_control_info {
	u8  oper_version;
	u8  max_version;
	u32 seqno;
	u32 ackno;
};
#pragma pack() /*packoff*/

struct unpacked_tlv *bld_dcbx1_tlv(struct dcbx_tlvs *dcbx);
struct unpacked_tlv *bld_dcbx2_tlv(struct dcbx_tlvs *dcbx);
struct unpacked_tlv *bld_dcbx_ctrl_tlv(struct dcbx_tlvs *dcbx);
struct unpacked_tlv *bld_dcbx1_pg_tlv(struct dcbx_tlvs *, bool *success);
struct unpacked_tlv *bld_dcbx2_pg_tlv(struct dcbx_tlvs *, bool *success);
struct unpacked_tlv *bld_dcbx1_pfc_tlv(struct dcbx_tlvs *, bool *success);
struct unpacked_tlv *bld_dcbx2_pfc_tlv(struct dcbx_tlvs *, bool *success);
struct unpacked_tlv *bld_dcbx1_app_tlv(struct dcbx_tlvs *dcbx, u32 sub_type,
					bool *success);
struct unpacked_tlv *bld_dcbx2_app_tlv(struct dcbx_tlvs *, bool *success);
struct unpacked_tlv *bld_dcbx_llink_tlv(struct dcbx_tlvs *, u32 sub_type,
					bool *success);

bool   unpack_dcbx1_tlvs(struct port *, struct lldp_agent *, struct unpacked_tlv *);
bool   unpack_dcbx2_tlvs(struct port *, struct lldp_agent *, struct unpacked_tlv *);
bool   process_dcbx_ctrl_tlv(struct port *, struct lldp_agent *);
bool   process_dcbx_pg_tlv(struct port *, struct lldp_agent *);
bool   process_dcbx_pfc_tlv(struct port *, struct lldp_agent *);
bool   process_dcbx_app_tlv(struct port *, struct lldp_agent *);
bool   process_dcbx_llink_tlv(struct port *, struct lldp_agent *);

#endif
