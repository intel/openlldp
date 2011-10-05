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

#ifndef _DCB_PROTOCOL_H_
#define _DCB_PROTOCOL_H_

#include "lldp.h"
#include "dcb_types.h"


typedef enum {
	dcb_success = 0,
	dcb_failed,
	dcb_device_not_found,
	dcb_invalid_cmd,
	dcb_bad_params,
	dcb_peer_not_present,
	dcb_ctrl_vers_not_compatible,
	dcb_not_capable
} dcb_result;

/* Feature State Machine Error definitions */
#define FEAT_ERR_NONE       0x00 /* no error */
#define FEAT_ERR_MISMATCH   0x01 /* feature mismatch with peer */
#define FEAT_ERR_CFG        0x02 /* error setting feature configuration */
#define FEAT_ERR_MULTI_TLV  0x04 /* multiple feature TLVs rcvd from peer */
#define FEAT_ERR_PEER       0x08 /* peer error */
#define FEAT_ERR_MULTI_PEER 0x10 /* multiple LLDP neighbors present */
#define FEAT_ERR_NO_TLV     0x20 /* feature not present in peer tlv */

/* Peer Error_Flag bits */
#define DUP_DCBX_TLV_CTRL          0x0001
#define DUP_DCBX_TLV_PG            0x0002
#define DUP_DCBX_TLV_PFC           0x0004
#define DUP_DCBX_TLV_APP           0x0010
#define DUP_DCBX_TLV_LLINK         0x0020
#define TOO_MANY_NGHBRS            0x0040

#define INIT_DCB_OUI                    {0x00,0x1b,0x21}

int dcbx_add_adapter(char *device_name);
int dcbx_remove_adapter(char *device_name);
int dcbx_remove_all(void);

bool init_dcb_support(char *device_name, full_dcb_attribs *attribs);
dcb_result get_dcb_support(char *device_name, struct feature_support *dcb_capabilites);
void remove_dcb_support(void);

/* unique strings for default data storage */
#define DEF_CFG_STORE "default_cfg_attribs"  /* Localization OK */
#define DEF_CFG_NUM   1

#define SUBTYPE_DEFAULT 0

bool add_pg_defaults(void);
bool add_pfc_defaults(void);
bool add_app_defaults(u32 subtype);
void mark_pg_sent(char *device_name);
void mark_pfc_sent(char *device_name);
void mark_app_sent(char *device_name, u32 subtype);
bool add_llink_defaults(u32 subtype);
void mark_llink_sent(char *device_name, u32 subtype);

dcb_result get_control(char *device_name,
	control_protocol_attribs *control_data);
dcb_result get_peer_control(char *device_name,
	control_protocol_attribs *control_data);
dcb_result put_peer_control(char *, control_protocol_attribs *);

dcb_result get_pg(char *device_name, pg_attribs *pg_data);
dcb_result put_pg(char *device_name, pg_attribs *pg_data,
		  pfc_attribs *pfc_data);
dcb_result put_peer_pg(char *,  pg_attribs *);
dcb_result get_oper_pg(char *device_name, pg_attribs *pg_data);
dcb_result get_peer_pg(char *device_name, pg_attribs *pg_data);

dcb_result get_pfc(char *device_name, pfc_attribs *pfc_data);
dcb_result put_pfc(char *device_name, pfc_attribs *pfc_data);
dcb_result put_peer_pfc(char *, pfc_attribs *);
dcb_result get_oper_pfc(char *device_name, pfc_attribs *pfc_data);
dcb_result get_peer_pfc(char *device_name, pfc_attribs *pfc_data);

dcb_result get_all_bwg_descrpts(char *device_name, pg_info *names);
dcb_result get_bwg_descrpt(char *device_name, u8 bwgid, char **name);
dcb_result put_bwg_descrpt(char *device_name, u8 bwgid, char *name);

dcb_result get_app(char *device_name, u32 subtype, app_attribs *app_data); 
dcb_result put_app(char *device_name, u32 subtype, app_attribs *app_data);
dcb_result put_peer_app(char *device_name, u32 subtype, app_attribs *);
dcb_result get_oper_app(char *device_name, u32 subtype, app_attribs *app_data);
dcb_result get_peer_app(char *device_name, u32 subtype, app_attribs *app_data);

dcb_result get_llink(char *device_name, u32 subtype, llink_attribs *llink_data);
dcb_result put_llink(char *device_name, u32 subtype, llink_attribs *llink_data);
dcb_result put_peer_llink(char *, u32 subtype, llink_attribs *);
dcb_result get_oper_llink(char *device_name, u32 subtype,
				llink_attribs *llink_data);
dcb_result get_peer_llink(char *device_name, u32 subtype,
				llink_attribs *llink_data);

dcb_result dcb_check_config(full_dcb_attrib_ptrs *attribs);
void rebalance_uppcts(pg_attribs *pg);

dcb_result run_feature_protocol(char *device_name, u32 EventFlag, u32 Subtype);
dcb_result run_control_protocol(char *device_name, u32 EventFlag);
dcb_result run_dcb_protocol(char *device_name, u32 EventFlag, u32 Subtype);

void remove_all_adapters(void);

dcb_result save_dcbx_state(const char *device_name);
int set_dcbx_state(const char *device_name, dcbx_state *state);
int get_dcbx_state(const char *device_name, dcbx_state *state);
int clear_dcbx_state();

#endif /*_DCB_PROTOCOL_H_ */
