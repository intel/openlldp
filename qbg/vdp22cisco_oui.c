/*******************************************************************************

  Implementation of Cisco Specific OUI for VDP2.2
  Copyright (c) 2012-2014 by Cisco Systems, Inc.

  Author(s): Padmanabhan Krishnan <padkrish at cisco dot com>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "messages.h"
#include "qbg_vdp22def.h"
#include "vdp_cisco.h"

struct vdp22_oui_handler_s cisco_oui_hndlr = {
		{0x00, 0x00, 0x0c}, "cisco", cisco_str2vdpnl_hndlr,
		cisco_vdpnl2vsi22_hndlr,
		cisco_vdp_tx_hndlr, cisco_vdp_rx_hndlr, cisco_vdp_free_oui,
		cisco_vdp_oui_ptlvsize};

struct oui_keyword_handler oui_key_handle[] = {
	{CISCO_OUI_NAME_ARG_STR, CISCO_OUI_NAME_ARG},
	{CISCO_OUI_NAME_UUID_ARG_STR, CISCO_OUI_NAME_UUID_ARG},
	{CISCO_OUI_L3V4ADDR_ARG_STR, CISCO_OUI_L3V4ADDR_ARG} };

enum oui_key_arg get_oui_key(char *token, u8 key_len)
{
	int count, key_str_size;

	key_str_size = sizeof(oui_key_handle) / sizeof(oui_key_handle[0]);
	for (count = 0; count < key_str_size; count++) {
		if ((key_len <= strlen(token)) &&
		     (!strncmp(token, oui_key_handle[count].keyword, key_len)))
			return oui_key_handle[count].val;
	}
	return CISCO_OUI_INVALID_ARG;
}

/*
 * This function fills the vdpnl structure of OUI from the command separated
 * arguments containing the OUI information.
 * The input to this function is right from the OUI data after the ORG specific
 * OUI Type.
 */

bool cisco_str2vdpnl_hndlr(struct vdpnl_oui_data_s *vdp_oui_p, char *token)
{
	vdp_cisco_oui_t *vdp_cisco_oui_p;
	char *uuid, *v4_addr_str;
	int ret, offset = 0, len;
	bool vm_name_flag = false, l3_addr_flag = false;
	enum oui_key_arg oui_argtype;
	u16 data_len;
	u8 key_len;

	if ((vdp_oui_p == NULL) || (token == NULL)) {
		LLDPAD_ERR("%s: NULL arg\n", __func__);
		return false;
	}
	fill_cisco_oui_type(vdp_oui_p->oui_type);
	vdp_oui_p->len = sizeof(vdp_cisco_oui_t);
	vdp_cisco_oui_p = (vdp_cisco_oui_t *)vdp_oui_p->data;
	len = strlen(token);
	while (offset < len) {
		oui_vdp_hexstr2bin(token, &key_len, sizeof(key_len));
		token += 2;
		offset += 2;
		oui_argtype = get_oui_key(token, key_len);
		token += key_len;
		offset += key_len;
		oui_vdp_hexstr2bin(token, (u8 *)&data_len, sizeof(data_len));
		data_len = htons(data_len);
		token += 4;
		offset += 4;
		if ((offset + data_len) > len) {
			LLDPAD_ERR("%s Incorrect len offset %d key %d data %d"
					" Len %d\n", __func__, offset, key_len,
					data_len, len);
			return false;
		}
		switch (oui_argtype) {
		case CISCO_OUI_NAME_ARG:
			if (vm_name_flag) {
				LLDPAD_ERR("%s: Incorrect arguments: Single VSI"
					   " containing multiple VM Name\n",
					   __func__);
				return false;
			}
			vm_name_flag = true;
			strncpy(vdp_cisco_oui_p->vm_name, token, data_len);
			vdp_cisco_oui_p->vm_name[data_len] = '\0';
			vdp_cisco_oui_p->vm_name_len = data_len;
			LLDPAD_DBG("Name %s Len %ld\n",
				   vdp_cisco_oui_p->vm_name,
				   vdp_cisco_oui_p->vm_name_len);
			break;
		case CISCO_OUI_NAME_UUID_ARG:
			uuid = calloc(data_len, sizeof(char));
			if (uuid == NULL) {
				LLDPAD_ERR("%s: NULL uuid\n", __func__);
				return false;
			}
			strncpy(uuid, token, data_len);
			if (oui_vdp_str2uuid(vdp_cisco_oui_p->uuid, uuid,
					     sizeof(vdp_cisco_oui_p->uuid)))
				memset(vdp_cisco_oui_p->uuid, 0,
					sizeof(vdp_cisco_oui_p->uuid));
			free(uuid);
			break;
		case CISCO_OUI_L3V4ADDR_ARG:
			if (l3_addr_flag) {
				LLDPAD_ERR("%s: Incorrect arguments: Single VSI"
					   " containing multiple L3 Address\n",
					   __func__);
				return true;
			}
			l3_addr_flag = true;
			vdp_cisco_oui_p->afi = MANADDR_IPV4;
			vdp_cisco_oui_p->vm_addr_len =
				sizeof(vdp_cisco_oui_p->l3_addr.ipv4_address);
			v4_addr_str = calloc(data_len, sizeof(char));
			if (v4_addr_str == NULL) {
				LLDPAD_ERR("%s: NULL L3 Address\n", __func__);
				return false;
			}
			strncpy(v4_addr_str, token, data_len);
			ret = inet_aton(v4_addr_str,
					&vdp_cisco_oui_p->l3_addr.ipv4_address);
			LLDPAD_DBG("V4adr %s 0x%lx\n", v4_addr_str,
				   (unsigned long)
				  vdp_cisco_oui_p->l3_addr.ipv4_address.s_addr);
			free(v4_addr_str);
			if (!ret) {
				LLDPAD_ERR("%s: Incorrect addr\n", __func__);
				return false;
			}
			break;
		default:
			LLDPAD_ERR("%s: unknown subtype %d\n", __func__,
				   oui_argtype);
			return false;
		}
		token += data_len;
		offset += data_len;
	}
	return true;
}

/*
 * This function converts the OUI information from vdpnl struct to vdp22 struct
 * vsi is not used here, but can be used for storing the pointer to the parent
 * struct
 */

bool cisco_vdpnl2vsi22_hndlr(void *vsi_data, struct vdpnl_oui_data_s *from,
			     struct vdp22_oui_data_s *to)
{
	if ((from == NULL) || (to == NULL)) {
		LLDPAD_ERR("%s: NULL arg\n", __func__);
		return false;
	}
	to->data = calloc(1, from->len);
	if (to->data == NULL) {
		LLDPAD_ERR("%s: calloc failure\n", __func__);
		return false;
	}
	memcpy(to->oui_type, from->oui_type, sizeof(to->oui_type));
	strncpy(to->oui_name, from->oui_name, sizeof(to->oui_name));
	/* Parent Pointer */
	to->vsi_data = vsi_data;
	to->len = from->len;
	memcpy(to->data, from->data, to->len);
	return true;
}

/*
 * This function deletes the OUI information associated with a VSI
 */

bool cisco_vdp_free_oui(struct vdp22_oui_data_s *vdp_oui_p)
{
	if ((vdp_oui_p == NULL) || (vdp_oui_p->data == NULL)) {
		LLDPAD_ERR("%s: NULL arg\n", __func__);
		return false;
	}
	free(vdp_oui_p->data);
	vdp_oui_p->len = 0;
	vdp_oui_p->data = NULL;
	return true;
}

/*
 * This gets called for any VDP specific response. Currently not implemented.
 */

bool cisco_vdp_rx_hndlr()
{
	return true;
}

static inline unsigned long cisco_vdp_name_subtlv_len(vdp_cisco_oui_t *ptr)
{
	return CISCO_VM_NAME_TLV_LEN + ptr->vm_name_len;
}

static inline unsigned long cisco_vdp_l3addr_subtlv_len(vdp_cisco_oui_t *ptr)
{
	return CISCO_VM_L3ADDR_TLV_LEN + ptr->vm_addr_len;
}

/*
 * Returns the size
 * ORG TLV's are sent separately for Name and IP, which is why the T,L of 2B
 * and 3B for OUI_TYPE_LEN is added for both. This is done to be compatible
 * with Cisco switch implementation.
 */

unsigned long cisco_vdp_oui_ptlvsize(void *arg_ptr)
{
	vdp_cisco_oui_t *ptr = (vdp_cisco_oui_t *)arg_ptr;
	unsigned long cnt = 0;

	if (ptr == NULL) {
		LLDPAD_ERR("%s: Incorrect arg\n", __func__);
		return 0;
	}
	if (ptr->vm_name_len != 0) {
		cnt += 2 + VDP22_OUI_TYPE_LEN;
		cnt += cisco_vdp_name_subtlv_len(ptr);
	}
	/* Only V4 or V6 is supported */
	if ((ptr->afi == MANADDR_IPV4) || (ptr->afi == MANADDR_IPV6)) {
		cnt += 2 + VDP22_OUI_TYPE_LEN;
		cnt += cisco_vdp_l3addr_subtlv_len(ptr);
	}
	return cnt;
}

static inline size_t cisco_vdp22_gen_l3addr(char unsigned *cp, size_t offset,
					    struct vdp22_oui_data_s *oui_ptr)
{
	vdp_cisco_oui_t *vdp_cisco_oui_str;
	unsigned char *vsi = NULL;
	unsigned short head;
	unsigned char len = 0;
	unsigned long net_l3_addr;

	vdp_cisco_oui_str = (vdp_cisco_oui_t *)oui_ptr->data;
	head = oui_get_tlv_head(VDP22_OUI, VDP22_OUI_TYPE_LEN +
				cisco_vdp_l3addr_subtlv_len(oui_ptr->data));
	offset += oui_append_2o(cp + offset, head);
	offset += oui_append_3o(cp + offset, CISCO_OUI_HEX);
	offset += oui_append_1o(cp + offset, CISCO_OUI_L3ADDR_SUBTYPE);
	offset += oui_append_1o(cp + offset,
				vdp22_oui_get_vsi22_fmt(oui_ptr->vsi_data));
	vsi = vdp22_oui_get_vsi22_len(oui_ptr->vsi_data, &len);
	if (vsi != NULL)
		offset += oui_append_nb(cp + offset, vsi, len);
	else
		LLDPAD_ERR("%s: get vsi22 return error\n", __func__);
	offset += oui_append_2o(cp + offset, vdp_cisco_oui_str->afi);
	if (vdp_cisco_oui_str->afi == MANADDR_IPV4) {
		net_l3_addr = htonl(vdp_cisco_oui_str->l3_addr.
				    ipv4_address.s_addr);
		offset += oui_append_4o(cp + offset, net_l3_addr);
	} else {
		offset += oui_append_4o(cp + offset, 0);
		LLDPAD_ERR("%s: Not supported for now\n", __func__);
	}
	LLDPAD_DBG("%s: Valid VM Addr offset %ld\n", __func__, offset);
	return offset;
}

static inline size_t cisco_vdp22_gen_vmname(char unsigned *cp, size_t offset,
					    struct vdp22_oui_data_s *oui_ptr)
{
	vdp_cisco_oui_t *vdp_cisco_oui_str;
	unsigned char *vsi = NULL;
	unsigned short head;
	unsigned char len = 0;

	vdp_cisco_oui_str = (vdp_cisco_oui_t *)oui_ptr->data;
	head = oui_get_tlv_head(VDP22_OUI, VDP22_OUI_TYPE_LEN +
				cisco_vdp_name_subtlv_len(oui_ptr->data));
	offset += oui_append_2o(cp + offset, head);
	offset += oui_append_3o(cp + offset, CISCO_OUI_HEX);
	offset += oui_append_1o(cp + offset, CISCO_OUI_NAME_SUBTYPE);
	offset += oui_append_1o(cp + offset,
				vdp22_oui_get_vsi22_fmt(oui_ptr->vsi_data));
	vsi = vdp22_oui_get_vsi22_len(oui_ptr->vsi_data, &len);
	if (vsi != NULL)
		offset += oui_append_nb(cp + offset, vsi, len);
	else
		LLDPAD_ERR("%s: get vsi22 return error\n", __func__);
	offset += oui_append_1o(cp + offset, VDP22_ID_UUID);
	offset += oui_append_nb(cp + offset, vdp_cisco_oui_str->uuid,
				sizeof(vdp_cisco_oui_str->uuid));
	offset += oui_append_nb(cp + offset,
				(char unsigned *)vdp_cisco_oui_str->vm_name,
				vdp_cisco_oui_str->vm_name_len);
	LLDPAD_DBG("%s: Valid VM Name offset %ld\n", __func__, offset);
	return offset;
}

/*
 * This function takes care of converting the OUI for Tx.
 */

size_t cisco_vdp_tx_hndlr(char unsigned *cp, struct vdp22_oui_data_s *oui_ptr,
			  size_t offset)
{
	vdp_cisco_oui_t *vdp_cisco_oui_str;

	if ((cp == NULL) || (oui_ptr == NULL) || (oui_ptr->data == NULL)) {
		LLDPAD_ERR("%s: NULL Arguments\n", __func__);
		return 0;
	}
	vdp_cisco_oui_str = (vdp_cisco_oui_t *)oui_ptr->data;
	if (vdp_cisco_oui_str->vm_name_len != 0)
		offset = cisco_vdp22_gen_vmname(cp, offset, oui_ptr);
	if (vdp_cisco_oui_str->vm_addr_len != 0)
		offset = cisco_vdp22_gen_l3addr(cp, offset, oui_ptr);
	return offset;
}

bool cisco_oui_init()
{
	bool ret;

	ret = oui_vdp_hndlr_init(&cisco_oui_hndlr);
	if (!ret) {
		LLDPAD_ERR("%s: handler init return err\n", __func__);
		return false;
	}
	return true;
}
