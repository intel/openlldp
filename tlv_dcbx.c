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

#include <stdlib.h>
#include <assert.h>
#include "lldp.h"
#include "dcb_types.h"
#include "lldp_tlv.h"
#include "tlv_dcbx.h"
#include "dcb_protocol.h"
#include "lldp_dcbx.h"
#include "lldp/states.h"
#include "lldp/agent.h"
#include "messages.h"

bool process_dcbx_ctrl_tlv(struct port *port, struct lldp_agent *);
bool process_dcbx_pg_tlv(struct port *port, struct lldp_agent *);
bool process_dcbx_pfc_tlv(struct port *port, struct lldp_agent *);
bool process_dcbx_app_tlv(struct port *port, struct lldp_agent *);
bool process_dcbx_llink_tlv(struct port *port, struct lldp_agent *);

/* for the specified remote feature, if the feature is not present in the
 * EventFlag parameter (indicating it was not received in the DCB TLV), then
 * check and update the peer data store object for the feature if it is
 * currently marked as being present.
 *
 * returns true if the feature is not present now
 *              the peer data store feature object is set to 'not present'
 *         false otherwise.
*/
static u32 check_feature_not_present(char *device_name, u32 subtype,
				u32 EventFlag, u32 feature)
{
	pg_attribs   peer_pg;
	pfc_attribs  peer_pfc;
	app_attribs  peer_app;
	llink_attribs  peer_llink;

	/* if (!DCB_TEST_FLAGS(EventFlag, feature, feature)) { */
	if (DCB_TEST_FLAGS(EventFlag, feature, feature))
		return false;

	switch (feature) {
	case DCB_REMOTE_CHANGE_PG:
		if ((get_peer_pg(device_name, &peer_pg) == cmd_success)
			&& (peer_pg.protocol.TLVPresent == true)) {
			peer_pg.protocol.TLVPresent = false;
			put_peer_pg(device_name, &peer_pg);
		}
		break;
	case DCB_REMOTE_CHANGE_PFC:
		if ((get_peer_pfc(device_name, &peer_pfc) == cmd_success)
			 && (peer_pfc.protocol.TLVPresent == true)) {
			peer_pfc.protocol.TLVPresent = false;
			put_peer_pfc(device_name, &peer_pfc);
		}
		break;
	case DCB_REMOTE_CHANGE_LLINK:
		if ((get_peer_llink(device_name, subtype, &peer_llink) ==
			cmd_success) && (peer_llink.protocol.TLVPresent ==
			true)) {
			peer_llink.protocol.TLVPresent = false;
			put_peer_llink(device_name, subtype, &peer_llink);
		}
		break;
	default:
		if (feature & DCB_REMOTE_CHANGE_APPTLV(subtype)) {
			if ((get_peer_app(device_name, subtype, &peer_app) ==
				cmd_success) &&
				(peer_app.protocol.TLVPresent == true)) {
				peer_app.protocol.TLVPresent = false;
				peer_app.Length = 0;
				put_peer_app(device_name, subtype, &peer_app);
			}
		}
		break;
	}

	return true;
}

struct unpacked_tlv *bld_dcbx1_tlv(struct dcbx_tlvs *dcbx)
{
	struct unpacked_tlv *tlv = create_tlv();
	struct  packed_tlv *ptlv =  NULL;
	u8 oui[DCB_OUI_LEN] = INIT_DCB_OUI;
	u8 subtype = dcbx_subtype1;
	u32 offset = 0;

	if (!tlv)
		return NULL;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = DCB_OUI_LEN + OUI_SUBTYPE_LEN;
	if (dcbx->control) {
		tlv->length = tlv->length + dcbx->control->length;
		if (dcbx->control->length) tlv->length+=2;
	}
	if (dcbx->pg1) {
		tlv->length = tlv->length + dcbx->pg1->length;
		if (dcbx->pg1->length) tlv->length+=2;
	}
	if (dcbx->pfc1) {
		tlv->length = tlv->length + dcbx->pfc1->length;
		if (dcbx->pfc1->length) tlv->length+=2;
	}
	if (dcbx->app1) {
		tlv->length = tlv->length + dcbx->app1->length;
		tlv->length+=2;
	}
	if (dcbx->llink) {
		tlv->length = tlv->length + dcbx->llink->length;
		if (dcbx->llink->length) tlv->length+=2;
	}

	tlv->info = (u8 *)malloc(tlv->length);
	if (tlv->info == NULL)
		goto error;
	memset(tlv->info,0, tlv->length);

	if ((DCB_OUI_LEN + OUI_SUBTYPE_LEN) > tlv->length)
		goto error;
	memcpy(tlv->info, &oui, DCB_OUI_LEN);
	offset += DCB_OUI_LEN;
	memcpy(&tlv->info[offset], &subtype, OUI_SUBTYPE_LEN);
	offset += OUI_SUBTYPE_LEN;

	if (tlv_ok(dcbx->control)) {
		ptlv =  pack_tlv(dcbx->control);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->pg1)) {
		ptlv = pack_tlv(dcbx->pg1);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->pfc1)) {
		ptlv = pack_tlv(dcbx->pfc1);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->app1)) {
		ptlv = pack_tlv(dcbx->app1);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}

	if (tlv_ok(dcbx->llink)) {
		ptlv = pack_tlv(dcbx->llink);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}

	if (offset != tlv->length)
		LLDPAD_DBG("assert offset == tlv->length\n");
	assert(offset == tlv->length);
	return tlv;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (tlv) {
		if (tlv->info)
			free(tlv->info);
		free(tlv);
	}
	LLDPAD_DBG("bld_dcbx1_tlv: malloc failure \n");
	return NULL;
}

struct unpacked_tlv *bld_dcbx2_tlv(struct dcbx_tlvs *dcbx)
{
	struct unpacked_tlv *tlv = create_tlv();
	struct packed_tlv *ptlv =  NULL;
	u8 oui[DCB_OUI_LEN] = INIT_DCB_OUI;
	u8 subtype = dcbx_subtype2;
	u32 offset = 0;

	if (!tlv)
		return NULL;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = DCB_OUI_LEN + OUI_SUBTYPE_LEN;
	if (dcbx->control) {
		tlv->length = tlv->length + dcbx->control->length;
		if (dcbx->control->length) tlv->length+=2;
	}
	if (dcbx->pg2) {
		tlv->length = tlv->length + dcbx->pg2->length;
		if (dcbx->pg2->length) tlv->length+=2;
	}
	if (dcbx->pfc2) {
		tlv->length = tlv->length + dcbx->pfc2->length;
		if (dcbx->pfc2->length) tlv->length+=2;
	}
	if (dcbx->app2) {
		tlv->length = tlv->length + dcbx->app2->length;
		tlv->length+=2;
	}

	tlv->info = (u8 *)malloc(tlv->length);
	if (tlv->info == NULL)
		goto error;
	memset(tlv->info,0, tlv->length);

	if ((DCB_OUI_LEN + OUI_SUBTYPE_LEN) > tlv->length)
		goto error;
	memcpy(tlv->info, &oui, DCB_OUI_LEN);
	offset += DCB_OUI_LEN;
	memcpy(&tlv->info[offset], &subtype, OUI_SUBTYPE_LEN);
	offset += OUI_SUBTYPE_LEN;

	if (tlv_ok(dcbx->control)) {
		ptlv =  pack_tlv(dcbx->control);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->pg2)) {
		ptlv = pack_tlv(dcbx->pg2);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->pfc2)) {
		ptlv = pack_tlv(dcbx->pfc2);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}
	if (tlv_ok(dcbx->app2)) {
		ptlv = pack_tlv(dcbx->app2);
		if (!ptlv || ((ptlv->size+offset) > tlv->length))
			goto error;
		memcpy(&tlv->info[offset], ptlv->tlv, ptlv->size);
		offset += ptlv->size;
		ptlv = free_pkd_tlv(ptlv);
	}

	if (offset != tlv->length)
		LLDPAD_DBG("assert offset == tlv->length\n");
	assert(offset == tlv->length);
	return tlv;

error:
	ptlv = free_pkd_tlv(ptlv);
	if (tlv) {
		if (tlv->info)
			free(tlv->info);
		free(tlv);
	}
	LLDPAD_DBG("bld_dcbx2_tlv: malloc failure \n");
	return NULL;
}

struct unpacked_tlv *bld_dcbx_ctrl_tlv(struct dcbx_tlvs *dcbx)
{
	struct unpacked_tlv *tlv = create_tlv();
	control_protocol_attribs ctrl_cfg;
	int i;
	u8 oper_version;
	u8 max_version;
	u32 seqno;
	u32 ackno;

	if (!tlv)
		return NULL;

	get_control(dcbx->ifname, &ctrl_cfg);
	oper_version = (u8)ctrl_cfg.Oper_version;
	max_version = (u8)ctrl_cfg.Max_version;
	seqno = htonl(ctrl_cfg.SeqNo);
	ackno = htonl(ctrl_cfg.AckNo);

	tlv->type = DCB_CONTROL_TLV;
	tlv->length = DCBX_CTRL_LEN;
	tlv->info = (u8 *)malloc(tlv->length);
	if (tlv->info) {
		memset(tlv->info,0, tlv->length);
		i = 0;
		memcpy(tlv->info, &oper_version, sizeof(oper_version));
		i += sizeof(oper_version);
		memcpy(tlv->info + i, &max_version, sizeof(max_version));
		i += sizeof(max_version);
		memcpy(tlv->info + i, &seqno, sizeof(seqno));
		i += sizeof(seqno);
		memcpy(tlv->info + i, &ackno ,sizeof(ackno));
		i = 0;
	} else {
		LLDPAD_DBG("bld_dcbx_ctrl_tlv: Failed to malloc info\n");
		free(tlv);
		return NULL;
	}

	return tlv;
}

struct unpacked_tlv *bld_dcbx1_pg_tlv(struct dcbx_tlvs *dcbx, bool *success)
{
	struct dcbx1_pg_info *pg_info;
	struct unpacked_tlv *tlv = create_tlv();
	pg_attribs  pg_cfg;
	int result, i;
	u8 tmpbyte = 0;

	*success = false;
	if (!tlv) {
		return NULL;
	}
	result = get_pg(dcbx->ifname, &pg_cfg);
	if (result == cmd_success) {
		mark_pg_sent(dcbx->ifname);
		if (!(pg_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}

	pg_info = (struct dcbx1_pg_info *)malloc(DCBX1_PG_LEN);
	if (pg_info) {
		memset(pg_info, 0, DCBX1_PG_LEN);
		pg_info->hdr.oper_version = (u8)pg_cfg.protocol.Oper_version;
		pg_info->hdr.max_version = (u8)pg_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if (pg_cfg.protocol.Enable == true)
			pg_info->hdr.ewe |= BIT7;
		if (pg_cfg.protocol.Willing == true)
			pg_info->hdr.ewe |= BIT6;
		if (pg_cfg.protocol.Error == true)
			pg_info->hdr.ewe |= BIT5;
		pg_info->hdr.sub_type = DEFAULT_SUBTYPE;

		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			pg_info->data.pg_percent[i] = pg_cfg.tx.pg_percent[i];
		}
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			tmpbyte = 0;
			tmpbyte = pg_cfg.tx.up[i].bwgid;
			tmpbyte = tmpbyte << 5;
			u8 tmpprio = 0;
			tmpprio = (u8)pg_cfg.tx.up[i].strict_priority;
			tmpprio = tmpprio << 3;
			tmpbyte |= tmpprio;
			pg_info->data.up_cfg[i].byte1 =	tmpbyte;
			pg_info->data.up_cfg[i].byte2 =
				pg_cfg.tx.up[i].percent_of_pg_cap;
		}

		tlv->length = DCBX1_PG_LEN;
	} else {
		LLDPAD_DBG("bld_dcbx1_pg_tlv: Failed to malloc pg_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_PRIORITY_GROUPS_TLV;
	tlv->info = (u8 *)pg_info;
	*success = true;
	return tlv;
}

struct unpacked_tlv *bld_dcbx2_pg_tlv(struct dcbx_tlvs *dcbx, bool *success)
{
	struct dcbx2_pg_info *pg_info;
	struct unpacked_tlv *tlv = create_tlv();
	pg_attribs  pg_cfg;
	int result, i;
	u8 tmpbyte = 0;
	int j, k;

	*success = false;
	if (!tlv) {
		return NULL;
	}
	result = get_pg(dcbx->ifname, &pg_cfg);
	if (result == cmd_success) {
		mark_pg_sent(dcbx->ifname);
		if (!(pg_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}

	pg_info = (struct dcbx2_pg_info *)malloc(DCBX2_PG_LEN);
	if (pg_info) {
		memset(pg_info, 0, DCBX2_PG_LEN);
		pg_info->hdr.oper_version = (u8)pg_cfg.protocol.Oper_version;
		pg_info->hdr.max_version = (u8)pg_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if (pg_cfg.protocol.Enable == true)
			pg_info->hdr.ewe |= BIT7;
		if (pg_cfg.protocol.Willing == true)
			pg_info->hdr.ewe |= BIT6;
		if (pg_cfg.protocol.Error == true)
			pg_info->hdr.ewe |= BIT5;
		pg_info->hdr.sub_type = DEFAULT_SUBTYPE;

		for (j=0,k=0 ; k < MAX_BANDWIDTH_GROUPS; j++, k=k+2) {
			tmpbyte = 0;
			if (pg_cfg.tx.up[k].strict_priority == dcb_link)
				tmpbyte = 0xf;
			else
				tmpbyte = pg_cfg.tx.up[k].pgid & 0xf;

			tmpbyte <<= 4;

			if (pg_cfg.tx.up[k+1].strict_priority == dcb_link)
				tmpbyte |= 0xf;
			else
				tmpbyte |= (pg_cfg.tx.up[k+1].pgid & 0xf);
			pg_info->data.pg_ids[j] = tmpbyte;
		}
		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			pg_info->data.pg_percent[i] = pg_cfg.tx.pg_percent[i];
		}
		pg_info->data.num_tcs = pg_cfg.num_tcs;

		tlv->length = DCBX2_PG_LEN;
	} else {
		LLDPAD_DBG("bld_dcbx2_pg_tlv: Failed to malloc pg_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_PRIORITY_GROUPS_TLV2;
	tlv->info = (u8 *)pg_info;
	*success = true;
	return tlv;
}

struct unpacked_tlv *bld_dcbx1_pfc_tlv(struct dcbx_tlvs *dcbx, bool *success)
{
	struct dcbx1_pfc_info *pfc_info;
	struct unpacked_tlv *tlv = create_tlv();
	pfc_attribs pfc_cfg;
	int result,i;

	*success = false;
	if (!tlv)
		return NULL;
	result = get_pfc(dcbx->ifname, &pfc_cfg);
	if (result == cmd_success) {
		mark_pfc_sent(dcbx->ifname);
		if (!(pfc_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}

	pfc_info = (struct dcbx1_pfc_info *)malloc(DCBX1_PFC_LEN);
	if (pfc_info) {
		memset(pfc_info, 0, DCBX1_PFC_LEN);
		pfc_info->hdr.oper_version = (u8)pfc_cfg.protocol.Oper_version;
		pfc_info->hdr.max_version = (u8)pfc_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if(pfc_cfg.protocol.Enable == true)
			pfc_info->hdr.ewe |= BIT7;
		if(pfc_cfg.protocol.Willing == true)
			pfc_info->hdr.ewe |= BIT6;
		if(pfc_cfg.protocol.Error == true)
			pfc_info->hdr.ewe |= BIT5;
		pfc_info->hdr.sub_type = DEFAULT_SUBTYPE;
		u8 temp = 0;
		for(i = 0; i < MAX_USER_PRIORITIES; i++) {
			temp = (u8)(pfc_cfg.admin[i] << i);
			pfc_info->data.admin_map |= temp;
		}

		tlv->length = DCBX1_PFC_LEN;
	} else {
		LLDPAD_DBG("bld_dcbx1_pfc_tlv: Failed to malloc pfc_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_PRIORITY_FLOW_CONTROL_TLV;
	tlv->info = (u8 *)pfc_info;
	*success = true;
	return tlv;
}

struct unpacked_tlv *bld_dcbx2_pfc_tlv(struct dcbx_tlvs *dcbx, bool *success)
{
	struct dcbx2_pfc_info *pfc_info;
	struct unpacked_tlv *tlv = create_tlv();
	pfc_attribs pfc_cfg;
	int result,i;

	*success = false;
	if (!tlv)
		return NULL;
	result = get_pfc(dcbx->ifname, &pfc_cfg);
	if (result == cmd_success) {
		mark_pfc_sent(dcbx->ifname);
		if (!(pfc_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}

	pfc_info = (struct dcbx2_pfc_info *)malloc(DCBX2_PFC_LEN);
	if (pfc_info) {
		memset(pfc_info, 0, DCBX2_PFC_LEN);
		pfc_info->hdr.oper_version = (u8)pfc_cfg.protocol.Oper_version;
		pfc_info->hdr.max_version = (u8)pfc_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if(pfc_cfg.protocol.Enable == true)
			pfc_info->hdr.ewe |= BIT7;
		if(pfc_cfg.protocol.Willing == true)
			pfc_info->hdr.ewe |= BIT6;
		if(pfc_cfg.protocol.Error == true)
			pfc_info->hdr.ewe |= BIT5;
		pfc_info->hdr.sub_type = DEFAULT_SUBTYPE;
		u8 temp = 0;
		for(i = 0; i < MAX_USER_PRIORITIES; i++) {
			temp = (u8)(pfc_cfg.admin[i] << i);
			pfc_info->data.admin_map |= temp;
		}
		pfc_info->data.num_tcs = pfc_cfg.num_tcs;

		tlv->length = DCBX2_PFC_LEN;
	} else {
		LLDPAD_DBG("bld_dcbx2_pfc_tlv: Failed to malloc pfc_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_PRIORITY_FLOW_CONTROL_TLV2;
	tlv->info = (u8 *)pfc_info;
	*success = true;
	return tlv;
}

struct unpacked_tlv *bld_dcbx1_app_tlv(struct dcbx_tlvs *dcbx,
					u32 sub_type,
					bool *success)
{
	struct dcbx1_app_info *app_info;
	struct unpacked_tlv *tlv = create_tlv();
	app_attribs     app_cfg;
	int result;
	u32 i,len;

	*success = false;
	if (!tlv)
		return NULL;

	memset(&app_cfg, 0, sizeof(app_cfg));
	result = get_app(dcbx->ifname, sub_type, &app_cfg);
	if (result == cmd_success) {
		mark_app_sent(dcbx->ifname);
		if (!(app_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}
	len = sizeof(struct  dcbx_tlv_header) + app_cfg.Length;
	app_info = (struct dcbx1_app_info *)malloc(len);
	if (app_info) {
		memset(app_info,0,sizeof(struct  dcbx1_app_info));
		app_info->hdr.oper_version = (u8)app_cfg.protocol.Oper_version;
		app_info->hdr.max_version = (u8)app_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if(app_cfg.protocol.Enable == true)
			app_info->hdr.ewe |= BIT7;
		if(app_cfg.protocol.Willing == true)
			app_info->hdr.ewe |= BIT6;
		if(app_cfg.protocol.Error == true)
			app_info->hdr.ewe |= BIT5;
		app_info->hdr.sub_type = (u8)sub_type;
		for (i = 0; i < app_cfg.Length; i++)
			app_info->data[i] = app_cfg.AppData[i];
		tlv->length = (u16)len;
	} else {
		LLDPAD_DBG("bld_dcbx1_app_tlv: Failed to malloc app_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_APPLICATION_TLV;
	tlv->info = (u8 *)app_info;
	*success = true;
	return tlv;
}

void set_proto(struct dcbx2_app_cfg *app_cfg, int subtype)
{
	u8 oui[DCB_OUI_LEN] = INIT_DCB_OUI;

	switch (subtype) {
	case APP_FCOE_STYPE:
		app_cfg->prot_id = PROTO_ID_FCOE;
		app_cfg->byte1 = (oui[0] & PROTO_ID_OUI_MASK)
			| (PROTO_ID_L2_ETH_TYPE & PROTO_ID_SF_TYPE);
		break;
	case APP_ISCSI_STYPE:
		app_cfg->prot_id = PROTO_ID_ISCSI;
		app_cfg->byte1 = (oui[0] & PROTO_ID_OUI_MASK)
			| (PROTO_ID_SOCK_NUM & PROTO_ID_SF_TYPE);
		break;
	case APP_FIP_STYPE:
		app_cfg->prot_id = PROTO_ID_FIP;
		app_cfg->byte1 = (oui[0] & PROTO_ID_OUI_MASK)
			| (PROTO_ID_L2_ETH_TYPE & PROTO_ID_SF_TYPE);
		break;
	}
	app_cfg->low_oui = (oui[2]<<8) | oui[1];
}

struct unpacked_tlv *bld_dcbx2_app_tlv(struct dcbx_tlvs *dcbx,
					bool *success)
{
	struct dcbx2_app_info *app_info;
	struct unpacked_tlv *tlv = create_tlv();
	app_attribs     app_cfg;
	int i, offset, result;
	bool advertise = false;

	*success = false;
	if (!tlv)
		return NULL;

	/* Verify there is something to advertise before building APP data */
	for (i = 0; i < DCB_MAX_APPTLV; i++) {
		memset(&app_cfg, 0, sizeof(app_cfg));
		result = get_app(dcbx->ifname, i, &app_cfg);
		if (result != cmd_success) {
			continue;
		} else if ((app_cfg.protocol.Advertise)) {
			advertise = true;
			break;
		}
	}

	if (!advertise) {
		free(tlv);
		*success = true;
		return NULL;
	}

	/* At least one APP entry exists so build the header and entries hdr
	 * values are taken from the first APP entry found. The APP order is
	 * set in dcb_types.h
	 */
	app_info = (struct dcbx2_app_info *)malloc(DCBX2_APP_LEN);
	tlv->length = DCBX2_APP_LEN;
	if (app_info) {
		struct dcbx2_app_cfg *app_data;

		memset(app_info, 0, DCBX2_APP_LEN);
		app_info->hdr.oper_version = (u8)app_cfg.protocol.Oper_version;
		app_info->hdr.max_version = (u8)app_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if(app_cfg.protocol.Enable == true)
			app_info->hdr.ewe |= BIT7;
		if(app_cfg.protocol.Willing == true)
			app_info->hdr.ewe |= BIT6;
		if(app_cfg.protocol.Error == true)
			app_info->hdr.ewe |= BIT5;
		app_info->hdr.sub_type = 0;

		for (offset = 0; i < DCB_MAX_APPTLV; i++) {
			result = get_app(dcbx->ifname, i, &app_cfg);
			if (result == cmd_success) {
				mark_app_sent(dcbx->ifname);
				if (!(app_cfg.protocol.Advertise))
					continue;
			}
			tlv->length += DCBX2_APP_SIZE;
			app_info = realloc(app_info, tlv->length);
			if (!app_info) {
				free(app_info);
				free(tlv);
				return NULL;
			}
			app_data = &(app_info->data[offset++]);
			set_proto(app_data, i);
			memcpy (&app_data->up_map, &(app_cfg.AppData[0]),
				APP_STYPE_LEN);
		}
	} else {
		LLDPAD_DBG("bld_dcbx2_app_tlv: Failed to malloc app_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_APPLICATION_TLV2;
	tlv->info = (u8 *)app_info;
	*success = true;
	return tlv;
}

struct unpacked_tlv *bld_dcbx_llink_tlv(struct dcbx_tlvs *dcbx, u32 sub_type,
					bool *success)
{
	struct dcbx_llink_info *llink_info;
	struct unpacked_tlv    *tlv = create_tlv();
	llink_attribs           llk_cfg;
	llink_cfg              *cfg;
	struct dcbx_llink_cfg  *pkt;
	int                     result;


	*success = false;
	if (!tlv) {
		return NULL;
	}
	result = get_llink(dcbx->ifname, sub_type, &llk_cfg);
	if (result == cmd_success) {
		mark_llink_sent(dcbx->ifname, sub_type);
		if (!(llk_cfg.protocol.Advertise)) {
			free(tlv);
			*success = true;
			return NULL;
		}
	} else {
		free(tlv);
		return NULL;
	}

	llink_info = (struct dcbx_llink_info *)malloc(DCBX_LLINK_LEN);
	if (llink_info) {
		memset(llink_info, 0, DCBX_LLINK_LEN);
		llink_info->hdr.oper_version =
			(u8)llk_cfg.protocol.Oper_version;
		llink_info->hdr.max_version = (u8)llk_cfg.protocol.Max_version;
		/* ewe Enable Willing Error */
		if (llk_cfg.protocol.Enable == true)
			llink_info->hdr.ewe |= BIT7;
		if (llk_cfg.protocol.Willing == true)
			llink_info->hdr.ewe |= BIT6;
		if (llk_cfg.protocol.Error == true)
			llink_info->hdr.ewe |= BIT5;
		llink_info->hdr.sub_type = (u8)sub_type;

		cfg = &(llk_cfg.llink);
		pkt = &(llink_info->data);

		if(cfg->llink_status == true)
			pkt->byte1 |= BIT7;
		tlv->length = DCBX_LLINK_LEN;
	} else {
		LLDPAD_DBG("bld_dcbx_llink_tlv: Failed to malloc llink_info\n");
		free(tlv);
		return NULL;
	}
	tlv->type = DCB_LLINK_TLV;
	tlv->info = (u8 *)llink_info;
	*success = true;
	return tlv;
}

bool unpack_dcbx1_tlvs(struct port *port, struct lldp_agent *agent,
		       struct unpacked_tlv *tlv)
{
	/* unpack the tlvs and store in manifest */
	u8 *offset = NULL;   /* iterator */
	u16 current = 0, tl = 0;
	u16 end = 0;         /* End of data blob */
	struct unpacked_tlv     *dcbtlv;
	struct dcbx_tlvs	*tlvs;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	/* store highest dcbx subtype received */
	if (agent->rx.dcbx_st < tlv->info[DCB_OUI_LEN]) {
		agent->rx.dcbx_st = tlv->info[DCB_OUI_LEN];
	}
	/* OUI + subtype sizes equal the start of data blob */
	offset = (u8  *)&tlv->info[OUI_SUBTYPE_LEN + DCB_OUI_LEN];
	end = tlv->length  - (OUI_SUBTYPE_LEN + DCB_OUI_LEN);

	/* Process */
	do {
		dcbtlv = create_tlv();
		if (!dcbtlv) {
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"DCB TLV. \n");
			return false;
		}
		memcpy(&tl, offset, sizeof(tl));
		offset += sizeof(tl);
		dcbtlv->length = ntohs(tl) & 0x01FF;
		if (dcbtlv->length==0) {
			LLDPAD_DBG("ERROR: dcbtlv->length==0 \n");
			free_unpkd_tlv(dcbtlv);
			return false;
		}
		dcbtlv->type   = (u8)(ntohs(tl) >> 9);
		dcbtlv->info = (u8 *)malloc(dcbtlv->length);
		if (dcbtlv->info) {
			memset(dcbtlv->info, 0, dcbtlv->length);
			memcpy(dcbtlv->info, offset, dcbtlv->length);
		} else {
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"TLV info \n");
			free_unpkd_tlv(dcbtlv);
			return false;
		}
		current += dcbtlv->length + sizeof(tl);
		offset += dcbtlv->length;
		switch(dcbtlv->type) {
		case DCB_CONTROL_TLV:
			if (!(tlvs->dcbdu & RCVD_DCBX1_TLV_CTRL)) {
				tlvs->dcbdu |= RCVD_DCBX1_TLV_CTRL;
				tlvs->manifest->dcbx_ctrl = dcbtlv;
			} else {
				LLDPAD_DBG("** ERROR: DUP Ctrl TLV1 \n");
				agent->rx.dupTlvs |= DUP_DCBX_TLV_CTRL;
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_PRIORITY_GROUPS_TLV:
			/* store if subtype 2 is not present */
			if (agent->rx.dcbx_st == dcbx_subtype1) {
				if (tlvs->manifest->dcbx_pg == NULL) {
					tlvs->dcbdu |= RCVD_DCBX_TLV_PG;
					tlvs->manifest->dcbx_pg = dcbtlv;
				} else {
					LLDPAD_DBG("** ERROR: DUP PG TLV1 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_PG;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_PRIORITY_FLOW_CONTROL_TLV:
			/* store if subtype 2 is not present */
			if (agent->rx.dcbx_st == dcbx_subtype1) {
				if (tlvs->manifest->dcbx_pfc == NULL) {
					tlvs->dcbdu |= RCVD_DCBX_TLV_PFC;
					tlvs->manifest->dcbx_pfc = dcbtlv;
				} else {
					LLDPAD_DBG("** ERROR: DUP PFC TLV1 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_PFC;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_APPLICATION_TLV:
			/* store if subtype 2 is not present */
			if ((agent->rx.dcbx_st == dcbx_subtype1) &&
				(dcbtlv->info[DCBX_HDR_SUB_TYPE_OFFSET]
					== APP_FCOE_STYPE)) {
				if (tlvs->manifest->dcbx_app == NULL) {
					tlvs->dcbdu |= RCVD_DCBX_TLV_APP;
					tlvs->manifest->dcbx_app = dcbtlv;
				} else {
					LLDPAD_DBG("** ERROR: DUP APP TLV1 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_APP;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
		break;
		case DCB_LLINK_TLV:
			if (dcbtlv->info[DCBX_HDR_SUB_TYPE_OFFSET]
					== LLINK_FCOE_STYPE) {
				if (tlvs->manifest->dcbx_llink == NULL) {
					tlvs->dcbdu |= RCVD_DCBX_TLV_LLINK;
					tlvs->manifest->dcbx_llink = dcbtlv;
				} else {
					LLDPAD_DBG("** ERROR: DUP LLINK TLV1 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_LLINK;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
		break;
		default:
			free_unpkd_tlv(dcbtlv);
		break;
		}
		dcbtlv = NULL;
	} while(current < end);

	return true;
}

bool unpack_dcbx2_tlvs(struct port *port, struct lldp_agent *agent,
		       struct unpacked_tlv *tlv)
{
	/* unpack the tlvs and store in manifest */
	u8 *offset = NULL;   /* iterator */
	u16 current = 0, tl = 0;
	u16 end = 0;         /* End of data blob */
	struct unpacked_tlv     *dcbtlv;
	struct dcbx_tlvs	*tlvs;
	int subtype;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	/* store highest dcbx subtype received */
	if (agent->rx.dcbx_st < tlv->info[DCB_OUI_LEN]) {
		agent->rx.dcbx_st = tlv->info[DCB_OUI_LEN];
	}
	/* OUI + subtype sizes equal the start of data blob */
	offset = (u8  *)&tlv->info[OUI_SUBTYPE_LEN + DCB_OUI_LEN];
	end = tlv->length  - (OUI_SUBTYPE_LEN + DCB_OUI_LEN);

	/* Process */
	do {
		dcbtlv = create_tlv();
		if (!dcbtlv) {
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"DCB TLV. \n");
			return false;
		}
		memcpy(&tl, offset, sizeof(tl));
		offset += sizeof(tl);
		dcbtlv->length = ntohs(tl) & 0x01FF;
		if (dcbtlv->length==0) {
			LLDPAD_DBG("ERROR: dcbtlv->length==0 \n");
			free_unpkd_tlv(dcbtlv);
			return false;
		}
		dcbtlv->type   = (u8)(ntohs(tl) >> 9);
		dcbtlv->info = (u8 *)malloc(dcbtlv->length);
		if (dcbtlv->info) {
			memset(dcbtlv->info, 0, dcbtlv->length);
			memcpy(dcbtlv->info, offset, dcbtlv->length);
		} else {
			LLDPAD_DBG("ERROR: Failed to malloc space for incoming "
				"TLV info \n");
			free_unpkd_tlv(dcbtlv);
			return false;
		}
		current += dcbtlv->length + sizeof(tl);
		offset += dcbtlv->length;
		switch(dcbtlv->type) {
		case DCB_CONTROL_TLV:
			if (tlvs->manifest->dcbx1 == NULL) {
				if (tlvs->manifest->dcbx_ctrl == NULL) {
					tlvs->dcbdu |= RCVD_DCBX2_TLV_CTRL;
					tlvs->manifest->dcbx_ctrl = dcbtlv;
				} else if (tlvs->dcbdu & RCVD_DCBX2_TLV_CTRL) {
					LLDPAD_DBG("** ERROR: DUP CTRL TLV2 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_CTRL;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_PRIORITY_GROUPS_TLV2:
			if (tlvs->manifest->dcbx_pg == NULL) {
				tlvs->dcbdu |= RCVD_DCBX_TLV_PG;
				tlvs->manifest->dcbx_pg = dcbtlv;
			} else {
				LLDPAD_DBG("** ERROR: DUP PG TLV2 \n");
				agent->rx.dupTlvs |= DUP_DCBX_TLV_PG;
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_PRIORITY_FLOW_CONTROL_TLV2:
			if (tlvs->manifest->dcbx_pfc == NULL) {
				tlvs->dcbdu |= RCVD_DCBX_TLV_PFC;
				tlvs->manifest->dcbx_pfc = dcbtlv;
			} else {
				LLDPAD_DBG("** ERROR: DUP PFC TLV2 \n");
				agent->rx.dupTlvs |= DUP_DCBX_TLV_PFC;
				free_unpkd_tlv(dcbtlv);
			}
			break;
		case DCB_APPLICATION_TLV2:
			subtype = dcbtlv->info[DCBX_HDR_SUB_TYPE_OFFSET];
			if (subtype == 0) {
				if (tlvs->manifest->dcbx_app == NULL) {
					tlvs->dcbdu |= RCVD_DCBX_TLV_APP;
					tlvs->manifest->dcbx_app = dcbtlv;
				} else {
					LLDPAD_DBG("** ERROR: DUP APP TLV2 \n");
					agent->rx.dupTlvs |= DUP_DCBX_TLV_APP;
					free_unpkd_tlv(dcbtlv);
				}
			} else {
				free_unpkd_tlv(dcbtlv);
			}
			break;
		default:
			free_unpkd_tlv(dcbtlv);
			break;
		}
		dcbtlv = NULL;
	} while(current < end);

	return true;
}

void  mibUpdateObjects(struct port *port, struct lldp_agent *agent)
{
	struct dcbx_tlvs *tlvs;
	u32 EventFlag = 0;
	int i;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return;

	if (tlvs->manifest->dcbx_ctrl) {
		if (process_dcbx_ctrl_tlv(port, agent) != true) {
			/* Error Set error condition for all features
			 * on this port and trash DCB TLV */
		}
	} else {
		/* Error Set error condition for all features
		 * on this port and trash DCB TLV */
	}
	if (tlvs->manifest->dcbx_pg) {
		if (process_dcbx_pg_tlv(port, agent) != true) {
			 /* mark feature not present */
			if (check_feature_not_present(port->ifname, 0,
				EventFlag, DCB_REMOTE_CHANGE_PG)) {
				DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG);
			}
		} else {
			DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG);
		}
	} else {
		if (check_feature_not_present(port->ifname, 0,
			EventFlag, DCB_REMOTE_CHANGE_PG)) {
			DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PG);
		}
	}
	if (tlvs->manifest->dcbx_pfc) {
		if (process_dcbx_pfc_tlv(port, agent) != true) {
			/* mark feature not present */
			if (check_feature_not_present(port->ifname, 0,
				EventFlag, DCB_REMOTE_CHANGE_PFC)) {
				DCB_SET_FLAGS(EventFlag,DCB_REMOTE_CHANGE_PFC);
			}
		 } else {
			 DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC);
		 }
	} else {
		if (check_feature_not_present(port->ifname, 0,
			EventFlag, DCB_REMOTE_CHANGE_PFC)) {
			DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_PFC);
		}
	}

	if (tlvs->manifest->dcbx_app) {
		bool ret = process_dcbx_app_tlv(port, agent);

		if (ret) {
			for (i = 0; i < DCB_MAX_APPTLV; i++)
				DCB_SET_FLAGS(EventFlag,
					      DCB_REMOTE_CHANGE_APPTLV(i));
		}
	} else {
		app_attribs peer_app;

		memset(&peer_app, 0, sizeof(app_attribs));
		for (i = 0; i < DCB_MAX_APPTLV; i++) {
			put_peer_app(port->ifname, i, &peer_app);
			DCB_SET_FLAGS(EventFlag,
				      DCB_REMOTE_CHANGE_APPTLV(i));
		}
	}

	if (tlvs->manifest->dcbx_llink) {
		if (process_dcbx_llink_tlv(port, agent) != true) {
			/* mark feature not present */
			if (check_feature_not_present(port->ifname, 0,
				EventFlag, DCB_REMOTE_CHANGE_LLINK)) {
				DCB_SET_FLAGS(EventFlag, 
					DCB_REMOTE_CHANGE_LLINK);
			}
		} else {
			 DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK);
		}
	} else {
		if (check_feature_not_present(port->ifname, 0,
			EventFlag, DCB_REMOTE_CHANGE_LLINK)) {
			DCB_SET_FLAGS(EventFlag, DCB_REMOTE_CHANGE_LLINK);
		}
	}

	/* Run the feature & control protocol for all features and subtypes */
	run_dcb_protocol(port->ifname, EventFlag, DCB_MAX_APPTLV+1);
	EventFlag = 0;
	agent->rxChanges = true;
	return;
}

bool process_dcbx_ctrl_tlv(struct port *port, struct lldp_agent *agent)
{
	struct dcbx_tlvs *tlvs;
	control_protocol_attribs  peer_control;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	if (tlvs->manifest->dcbx_ctrl->length != DCBX_CTRL_LEN) {
		LLDPAD_DBG("process_dcbx_ctrl_tlv: ERROR - len\n");
		return(false);
	}

	memset(&peer_control, 0, sizeof(control_protocol_attribs));
	peer_control.Oper_version =	tlvs->manifest->dcbx_ctrl->info
		[DCBX_CTRL_OPER_VER_OFFSET];
	peer_control.Max_version = tlvs->manifest->dcbx_ctrl->info
		[DCBX_CTRL_MAX_VER_OFFSET];

	u32 tmp32 = 0;
	memcpy(&tmp32, &tlvs->manifest->dcbx_ctrl->info
		[DCBX_CTRL_SEQNO_OFFSET], sizeof(u32));
	peer_control.SeqNo = ntohl(tmp32);
	tmp32 = 0;
	memcpy(&tmp32,&tlvs->manifest->dcbx_ctrl->info
		[DCBX_CTRL_ACKNO_OFFSET], sizeof(u32));
	peer_control.AckNo = ntohl(tmp32);
	LLDPAD_INFO("*** Received a DCB_CONTROL_TLV: -- SeqNo=%d, AckNo=%d \n",
		peer_control.SeqNo, peer_control.AckNo);
	peer_control.RxDCBTLVState = DCB_PEER_PRESENT;

	if (agent->rx.dupTlvs & DUP_DCBX_TLV_CTRL) {
		LLDPAD_INFO("** STORE: DUP CTRL TLV \n");
		peer_control.Error_Flag |= DUP_DCBX_TLV_CTRL;
	}
	if (agent->rx.tooManyNghbrs) {
		LLDPAD_INFO("** STORE: TOO_MANY_NGHBRS\n");
		peer_control.Error_Flag |= TOO_MANY_NGHBRS;
	}

	put_peer_control(port->ifname, &peer_control);

	return(true);
}

bool process_dcbx_pg_tlv(struct port *port, struct lldp_agent *agent)
{
	pg_attribs   peer_pg;
	struct dcbx_tlvs *tlvs;
	int i = 0;
	int j, k;
	u8 used[MAX_BANDWIDTH_GROUPS];

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	if (agent->rx.dcbx_st == dcbx_subtype2) {
		if (tlvs->manifest->dcbx_pg->length != DCBX2_PG_LEN) {
			LLDPAD_DBG("process_dcbx2_pg_tlv: ERROR - len\n");
			return(false);
		}
	} else {
		if (tlvs->manifest->dcbx_pg->length != DCBX1_PG_LEN) {
			LLDPAD_DBG("process_dcbx1_pg_tlv: ERROR - len\n");
			return(false);
		}
	}

	memset(&peer_pg, 0, sizeof(pg_attribs));
	peer_pg.protocol.Advertise = true;
	peer_pg.protocol.Oper_version =	tlvs->manifest->dcbx_pg->info
		[DCBX_HDR_OPER_VERSION_OFFSET];
	peer_pg.protocol.Max_version = tlvs->manifest->dcbx_pg->info
		[DCBX_HDR_MAX_VERSION_OFFSET];
	if (tlvs->manifest->dcbx_pg->info[DCBX_HDR_EWE_OFFSET] & BIT7) {
		peer_pg.protocol.Enable = true;
	} else {
		peer_pg.protocol.Enable = false;
	}
	if (tlvs->manifest->dcbx_pg->info[DCBX_HDR_EWE_OFFSET] & BIT6) {
		peer_pg.protocol.Willing = true;
	} else {
		peer_pg.protocol.Willing = false;
	}
	if (tlvs->manifest->dcbx_pg->info[DCBX_HDR_EWE_OFFSET] & BIT5) {
		peer_pg.protocol.Error = true;
	} else {
		peer_pg.protocol.Error = false;
	}
	peer_pg.protocol.dcbx_st = agent->rx.dcbx_st;
	peer_pg.protocol.TLVPresent = true;

	if (agent->rx.dupTlvs & DUP_DCBX_TLV_CTRL) {
		LLDPAD_INFO("** STORE: DUP CTRL TLV \n");
		peer_pg.protocol.Error_Flag |= DUP_DCBX_TLV_CTRL;
	}
	if (agent->rx.dupTlvs & DUP_DCBX_TLV_PG) {
		LLDPAD_INFO("** STORE: DUP PG TLV \n");
		peer_pg.protocol.Error_Flag |= DUP_DCBX_TLV_PG;
	}

	if (agent->rx.dcbx_st == dcbx_subtype2) {
		memset(used, false, sizeof(used));
		for (j=0,k=0 ; k < MAX_BANDWIDTH_GROUPS; j++, k=k+2) {
			u8 tmpbyte = tlvs->manifest->dcbx_pg->info
				[DCBX2_PG_PGID_UP+j];
			peer_pg.tx.up[k+1].pgid = tmpbyte & 0xf;
			peer_pg.rx.up[k+1].pgid = tmpbyte & 0xf;
			peer_pg.tx.up[k].pgid = (tmpbyte >> 4) & 0xf;
			peer_pg.rx.up[k].pgid = (tmpbyte >> 4) & 0xf;
			if (peer_pg.tx.up[k+1].pgid == LINK_STRICT_PGID) {
				peer_pg.tx.up[k+1].strict_priority = dcb_link;
				peer_pg.rx.up[k+1].strict_priority = dcb_link;
			} else {
				used[peer_pg.tx.up[k+1].pgid] = true;
			}
			if (peer_pg.tx.up[k].pgid == LINK_STRICT_PGID) {
				peer_pg.tx.up[k].strict_priority = dcb_link;
				peer_pg.rx.up[k].strict_priority = dcb_link;
			} else {
				used[peer_pg.tx.up[k].pgid] = true;
			}

			peer_pg.tx.up[k+1].bwgid = k + 1;
			peer_pg.rx.up[k+1].bwgid = k + 1;
			peer_pg.tx.up[k].bwgid = k;
			peer_pg.rx.up[k].bwgid = k;
		}
		/* assign LINK_STRICT_PGID's to an unused pgid value */
		for (j = 0; j < MAX_BANDWIDTH_GROUPS; j++)
			if (!used[j])
				break;
		for (k = 0; k < MAX_BANDWIDTH_GROUPS; k++) {
			if (peer_pg.tx.up[k].pgid == LINK_STRICT_PGID) {
				peer_pg.tx.up[k].pgid = (u8)j;
				peer_pg.rx.up[k].pgid = (u8)j;
			}
		}

		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			peer_pg.tx.pg_percent[i] =
				tlvs->manifest->dcbx_pg->info
				[DCBX2_PG_PERCENT_OFFSET + i];
			peer_pg.rx.pg_percent[i] =
				tlvs->manifest->dcbx_pg->info
				[DCBX2_PG_PERCENT_OFFSET + i];
		}
		peer_pg.num_tcs = (u8)(tlvs->manifest->dcbx_pg->info
				[DCBX2_PG_NUM_TC_OFFSET]);
	} else {
		for (i = 0; i < MAX_BANDWIDTH_GROUPS; i++) {
			peer_pg.tx.pg_percent[i] =
				tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_PERCENT_OFFSET + i];
			peer_pg.rx.pg_percent[i] =
				tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_PERCENT_OFFSET + i];
		}
		for (i = 0; i < MAX_USER_PRIORITIES; i++) {
			u8 tmp_bwg_id = tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_SETTINGS_OFFSET + 2*i +BYTE1_OFFSET];
			tmp_bwg_id = tmp_bwg_id >> 5;
			peer_pg.tx.up[i].bwgid = tmp_bwg_id;
			peer_pg.rx.up[i].bwgid = tmp_bwg_id;

			u8 tmp_strict_prio =
				tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_SETTINGS_OFFSET + 2*i +BYTE1_OFFSET];
			tmp_strict_prio = tmp_strict_prio >> 3;
			tmp_strict_prio &= 0x3;
			peer_pg.tx.up[i].strict_priority =
				(dcb_strict_priority_type)tmp_strict_prio;
			peer_pg.rx.up[i].strict_priority =
				(dcb_strict_priority_type)tmp_strict_prio;

			peer_pg.tx.up[i].percent_of_pg_cap =
				tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_SETTINGS_OFFSET + 2*i +BYTE2_OFFSET];
			peer_pg.rx.up[i].percent_of_pg_cap =
				tlvs->manifest->dcbx_pg->info
				[DCBX1_PG_SETTINGS_OFFSET + 2*i +BYTE2_OFFSET];
			tmp_bwg_id = tmp_strict_prio = 0;

			peer_pg.tx.up[i].pgid = i;
			peer_pg.rx.up[i].pgid = i;
		}
	}
	put_peer_pg(port->ifname, &peer_pg);

	return(true);
}

bool process_dcbx_pfc_tlv(struct port *port, struct lldp_agent *agent)
{
	pfc_attribs  peer_pfc;
	struct dcbx_tlvs *tlvs;
	int i = 0;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	if (agent->rx.dcbx_st == dcbx_subtype2) {
		if (tlvs->manifest->dcbx_pfc->length != DCBX2_PFC_LEN) {
			LLDPAD_DBG("process_dcbx2_pfc_tlv: ERROR - len\n");
			return(false);
		}
	} else {
		if (tlvs->manifest->dcbx_pfc->length != DCBX1_PFC_LEN) {
			LLDPAD_DBG("process_dcbx1_pfc_tlv: ERROR - len\n");
			return(false);
		}
	}

	memset(&peer_pfc, 0, sizeof(pfc_attribs));
	peer_pfc.protocol.Advertise = true;
	peer_pfc.protocol.Oper_version = tlvs->manifest->dcbx_pfc->info
		[DCBX_HDR_OPER_VERSION_OFFSET];
	peer_pfc.protocol.Max_version =	tlvs->manifest->dcbx_pfc->info
		[DCBX_HDR_MAX_VERSION_OFFSET];
	if (tlvs->manifest->dcbx_pfc->info[DCBX_HDR_EWE_OFFSET] & BIT7) {
		peer_pfc.protocol.Enable = true;
	} else {
		peer_pfc.protocol.Enable = false;
	}
	if (tlvs->manifest->dcbx_pfc->info[DCBX_HDR_EWE_OFFSET] & BIT6) {
		peer_pfc.protocol.Willing = true;
	} else {
		peer_pfc.protocol.Willing = false;
	}
	if (tlvs->manifest->dcbx_pfc->info[DCBX_HDR_EWE_OFFSET] & BIT5) {
		peer_pfc.protocol.Error = true;
	} else {
		peer_pfc.protocol.Error = false;
	}
	peer_pfc.protocol.dcbx_st = agent->rx.dcbx_st;
	peer_pfc.protocol.TLVPresent = true;

	if (agent->rx.dupTlvs & DUP_DCBX_TLV_CTRL) {
		LLDPAD_INFO("** STORE: DUP CTRL TLV \n");
		peer_pfc.protocol.Error_Flag |= DUP_DCBX_TLV_CTRL;
	}
	if (agent->rx.dupTlvs & DUP_DCBX_TLV_PFC) {
		LLDPAD_INFO("** STORE: DUP PFC TLV \n");
		peer_pfc.protocol.Error_Flag |= DUP_DCBX_TLV_PFC;
	}

	u8 temp = 0;
	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		temp = tlvs->manifest->dcbx_pfc->info[DCBX_PFC_MAP_OFFSET];
		peer_pfc.admin[i] = (pfc_type)((temp >> i) & BIT0);
	}
	if (agent->rx.dcbx_st == dcbx_subtype2) {
		peer_pfc.num_tcs = tlvs->manifest->dcbx_pfc->info
				[DCBX2_PFC__NUM_TC_OFFSET];
	}
	put_peer_pfc(port->ifname, &peer_pfc);

	return(true);
}

bool process_dcbx_app_tlv(struct port *port, struct lldp_agent *agent)
{
	app_attribs peer_app;
	u32         i=0, len=0;
	u8          sub_type=0, sel_field=0, *pBuf=NULL;
	u16         peer_proto=0;
	u8          oui[DCB_OUI_LEN]=INIT_DCB_OUI;
	u8          peer_oui[DCB_OUI_LEN];
	bool	fcoe, fip, iscsi;
	struct dcbx_tlvs *tlvs;

	fcoe = fip = iscsi = false;
	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	len = tlvs->manifest->dcbx_app->length;
	if (agent->rx.dcbx_st == dcbx_subtype2) {
		if (len < DCBX2_APP_LEN) {
			LLDPAD_DBG("process_dcbx2_app_tlv: ERROR - len\n");
			return(false);
		}
	} else {
		if (len < DCBX1_APP_LEN) {
			LLDPAD_DBG("process_dcbx1_app_tlv: ERROR - len\n");
			return(false);
		}
	}

	memset(&peer_oui, 0, DCB_OUI_LEN);
	memset(&peer_app, 0, sizeof(app_attribs));
	pBuf = tlvs->manifest->dcbx_app->info;

	peer_app.protocol.Oper_version = pBuf[DCBX_HDR_OPER_VERSION_OFFSET];
	peer_app.protocol.Max_version =	pBuf[DCBX_HDR_MAX_VERSION_OFFSET];
	if (pBuf[DCBX_HDR_EWE_OFFSET] & BIT7) {
		peer_app.protocol.Enable = true;
	} else {
		peer_app.protocol.Enable = false;
	}
	if (pBuf[DCBX_HDR_EWE_OFFSET] & BIT6) {
		peer_app.protocol.Willing = true;
	} else {
		peer_app.protocol.Willing = false;
	}
	if (pBuf[DCBX_HDR_EWE_OFFSET] & BIT5) {
		peer_app.protocol.Error = true;
	} else {
		peer_app.protocol.Error = false;
	}
	peer_app.protocol.dcbx_st = agent->rx.dcbx_st;

	if (agent->rx.dupTlvs & DUP_DCBX_TLV_CTRL) {
		LLDPAD_INFO("** STORE: DUP CTRL TLV \n");
		peer_app.protocol.Error_Flag |= DUP_DCBX_TLV_CTRL;
	}
	if (agent->rx.dupTlvs & DUP_DCBX_TLV_APP) {
		LLDPAD_INFO("** STORE: DUP APP TLV \n");
		peer_app.protocol.Error_Flag |= DUP_DCBX_TLV_APP;
	}

	if (agent->rx.dcbx_st == dcbx_subtype2) {
		/* processs upper layer protocol IDs until we 
		 * match Selector Field, FCoE or FIP ID and OUI */
		len -= DCBX2_APP_DATA_OFFSET;
		pBuf = &pBuf[DCBX2_APP_DATA_OFFSET];
		while (len >= DCBX2_APP_SIZE) {
			sel_field = (u8)(pBuf[DCBX2_APP_BYTE1_OFFSET] &
					 PROTO_ID_SF_TYPE);
			if (sel_field != PROTO_ID_L2_ETH_TYPE &&
			    sel_field != PROTO_ID_SOCK_NUM) {
				sel_field = 0;
				len -= DCBX2_APP_SIZE;
				pBuf += DCBX2_APP_SIZE;
				continue;
			}
			peer_proto = *((u16*)(&(pBuf[0])));
			if ((peer_proto != PROTO_ID_FCOE) && 
			    (peer_proto != PROTO_ID_ISCSI) &&
			    (peer_proto != PROTO_ID_FIP)) {
				sel_field = 0;
				peer_proto = 0;
				len -= DCBX2_APP_SIZE;
				pBuf += DCBX2_APP_SIZE;
				continue;
			}
			peer_oui[0] = (u8)(pBuf[DCBX2_APP_BYTE1_OFFSET] &
					   PROTO_ID_OUI_MASK);
			peer_oui[1] = pBuf[DCBX2_APP_LOW_OUI_OFFSET1];
			peer_oui[2] = pBuf[DCBX2_APP_LOW_OUI_OFFSET2];
			if (memcmp(peer_oui, oui, DCB_OUI_LEN) != 0) {
				sel_field = 0;
				peer_proto = 0;
				memset(&peer_oui, 0, DCB_OUI_LEN);
				len -= DCBX2_APP_SIZE;
				pBuf += DCBX2_APP_SIZE;
				continue;
			}

			if (sel_field == PROTO_ID_L2_ETH_TYPE &&
			    peer_proto == PROTO_ID_FCOE) {
				sub_type = APP_FCOE_STYPE;
				fcoe = true;
			} else if (sel_field == PROTO_ID_SOCK_NUM &&
				   peer_proto == PROTO_ID_ISCSI) {
				sub_type = APP_ISCSI_STYPE;
				iscsi = true;
			} else if (sel_field == PROTO_ID_L2_ETH_TYPE &&
				   peer_proto == PROTO_ID_FIP) {
				sub_type = APP_FIP_STYPE;
				fip = true;
			}

			peer_app.protocol.TLVPresent = true;
			peer_app.Length = APP_STYPE_LEN;
			memcpy (&(peer_app.AppData[0]), 
				&(pBuf[DCBX2_APP_UP_MAP_OFFSET]),
				peer_app.Length);
			put_peer_app(port->ifname, sub_type, &peer_app);
			len -= DCBX2_APP_SIZE;
			pBuf += DCBX2_APP_SIZE;
		}
		/* NULL APP entry if not in TLV */
		memset(&peer_app, 0, sizeof(app_attribs));
		if (!fcoe)
			put_peer_app(port->ifname, APP_FCOE_STYPE, &peer_app);
		if (!iscsi)
			put_peer_app(port->ifname, APP_ISCSI_STYPE, &peer_app);
		if (!fip)
			put_peer_app(port->ifname, APP_FIP_STYPE, &peer_app);
	} else if (agent->rx.dcbx_st == dcbx_subtype1) {
		sub_type = pBuf[DCBX_HDR_SUB_TYPE_OFFSET];
		len = tlvs->manifest->dcbx_app->length -
			sizeof(struct  dcbx_tlv_header);
		peer_app.Length = len;
		if (DCB_MAX_TLV_LENGTH < len) {
			return false;
		}
		for (i = 0; i < len; i++) {
			peer_app.AppData[i] = pBuf[DCBX1_APP_DATA_OFFSET + i];
		}
		peer_app.protocol.TLVPresent = true;
		put_peer_app(port->ifname, sub_type, &peer_app);
		return(true);
	} else {
		return false;
	}

	return true;
}

bool process_dcbx_llink_tlv(struct port *port, struct lldp_agent *agent)
{
	llink_attribs   peer_llk;
	struct dcbx_tlvs *tlvs;

	tlvs = dcbx_data(port->ifname);

	if (agent == NULL)
		return false;

	if (tlvs->manifest->dcbx_llink->length != DCBX_LLINK_LEN) {
		LLDPAD_DBG("process_dcbx_llink_tlv: ERROR - len\n");
		return(false);
	}

	memset(&peer_llk, 0, sizeof(llink_attribs));
	peer_llk.protocol.Advertise = true;
	peer_llk.protocol.Oper_version = tlvs->manifest->dcbx_llink->info
		[DCBX_HDR_OPER_VERSION_OFFSET];
	peer_llk.protocol.Max_version = tlvs->manifest->dcbx_llink->info
		[DCBX_HDR_MAX_VERSION_OFFSET];
	if (tlvs->manifest->dcbx_llink->info[DCBX_HDR_EWE_OFFSET] & BIT7) {
		peer_llk.protocol.Enable = true;
	} else {
		peer_llk.protocol.Enable = false;
	}
	if (tlvs->manifest->dcbx_llink->info[DCBX_HDR_EWE_OFFSET] & BIT6) {
		peer_llk.protocol.Willing = true;
	} else {
		peer_llk.protocol.Willing = false;
	}
	if (tlvs->manifest->dcbx_llink->info[DCBX_HDR_EWE_OFFSET] & BIT5) {
		peer_llk.protocol.Error = true;
	} else {
		peer_llk.protocol.Error = false;
	}
	peer_llk.protocol.dcbx_st = agent->rx.dcbx_st;
	peer_llk.protocol.TLVPresent = true;

	if (agent->rx.dupTlvs & DUP_DCBX_TLV_CTRL) {
		LLDPAD_INFO("** STORE: DUP CTRL TLV \n");
		peer_llk.protocol.Error_Flag |= DUP_DCBX_TLV_CTRL;
	}
	if (agent->rx.dupTlvs & DUP_DCBX_TLV_LLINK) {
		LLDPAD_INFO("** STORE: DUP LLINK TLV \n");
		peer_llk.protocol.Error_Flag |= DUP_DCBX_TLV_LLINK;
	}

	peer_llk.llink.llink_status = !!((tlvs->manifest->dcbx_llink->info
				[DCBX_LLINK_STATUS_OFFSET]) & BIT7);
	put_peer_llink(port->ifname, LLINK_FCOE_STYPE, &peer_llk);

	return(true);
}

