/******************************************************************************

  Implementation of VDP 2.2 bridge resource allocation simulator for LLDP
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

******************************************************************************/

/*
 * VDP22 bridge simulation code. For now return true all the time.
 * When configured with --enable-debug option
 * special combination of input parameters trigger errors decribed
 * below.
 *
 * TODO
 * Will be replaced by lldpad configuration file section to allow
 * rejection and acception of VSI profiles on a configurable bases.
 * For now this is good enough for basic state machine testing.
 */

#define _GNU_SOURCE
#include <string.h>

#include <net/if.h>
#include <netinet/in.h>

#include "messages.h"
#include "config.h"
#include "eloop.h"

#include "qbg22.h"
#include "qbg_vdp22.h"
#include "qbg_utils.h"

#ifdef BUILD_DEBUG
static unsigned char deassoc_buf[256];
static unsigned char ifname_buf[16];
static struct qbg22_imm deassoc_qbg;

static void deassoc(void *ctx, void *parm)
{
	struct qbg22_imm *qbg = (struct qbg22_imm *)parm;
	char *ifname = (char *)ctx;
	int rc;

	rc = modules_notify(LLDP_MOD_ECP22, LLDP_MOD_VDP22, ifname, qbg);
	LLDPAD_DBG("%s:%s leave rc:%d\n", __func__, ifname, rc);
}

static void trigger_deassoc(struct vdp22 *vdp)
{
	deassoc_qbg.data_type = VDP22_TO_ECP22;
	deassoc_qbg.u.c.len = vdp->input_len;
	deassoc_qbg.u.c.data = deassoc_buf;
	memcpy(deassoc_buf, vdp->input, vdp->input_len);
	deassoc_buf[18] = VDP22_DEASSOC << 1;	/* Offset of TLV */
	deassoc_buf[18 + 2] = 0;
	memcpy(ifname_buf, vdp->ifname, sizeof(ifname_buf));
	eloop_register_timeout(35, 0, deassoc, ifname_buf, &deassoc_qbg);
	LLDPAD_DBG("%s:%s vdp->input_len:%d\n", __func__, vdp->ifname,
		   vdp->input_len);
}

static void change_vlan0(struct vsi22 *p, unsigned short idx, int with_qos)
{
	if (p->fif == VDP22_FFMT_MACVID)
		p->fdata[idx].vlan = vdp22_set_vlanid(p->type_id);
	else
		p->fdata[idx].vlan = vdp22_set_vlanid(p->fdata[idx].grpid);
	if (with_qos)
		p->fdata[idx].vlan |= vdp22_set_qos(8 + (p->type_ver & 7));
}

static int change_fid(struct vsi22 *p)
{
	unsigned short idx = p->type_ver >> 4 & 0xf;

	if (idx >= p->no_fdata)
		return VDP22_RESP_NOADDR;
	if (p->type_id == 204) {
		p->fdata[idx].vlan = vdp22_set_vlanid(p->fdata[idx].grpid)
					| vdp22_set_qos(8 + (p->type_ver & 7));
	} else if (p->type_id == 205) {
		p->fdata[idx].vlan = vdp22_set_vlanid(p->type_id);
	} else if (p->type_id == 206) {
		p->fdata[idx].vlan = vdp22_get_vlanid(p->fdata[idx].vlan)
					| vdp22_set_qos(8 + (p->type_ver & 7));
	} else if (p->type_id == 207) {
		p->fdata[idx].vlan = vdp22_set_vlanid(p->fdata[idx].grpid);
	} else if (p->type_id == 208 && p->fif != VDP22_FFMT_VID) {
		int i;

		for (i = 0; i < p->no_fdata; ++i)
			if (!vdp22_get_vlanid(p->fdata[i].vlan))
				change_vlan0(p, i, idx);
	}
	return 0;
}
#endif

int vdp22br_resources(struct vsi22 *p, int *error)
{
	int rc = VDP22_RESP_SUCCESS;
	static unsigned long called;

	*error = 0;
	++called;
	LLDPAD_DBG("%s:%s vsi:%p(%02x) called:%ld id:%ld\n", __func__,
		   p->vdp->ifname, p, p->vsi[0], called, p->type_id);
	rc = (p->vsi_mode == VDP22_DEASSOC) ? VDP22_RESP_DEASSOC :
				VDP22_RESP_SUCCESS;
#ifdef BUILD_DEBUG
	/*
	 * Trigger errors
	 * Typeid 199 trigger delayed bridge resource availability
	 * Typeid 200 trigger de-assoc
	 * Typeid 201 trigger de-assoc error response
	 * Typeid 202 trigger keep error response with keep bit set
	 * Typeid 203 trigger de-assoc error response with hard bit set
	 * Typeid 199-202 type_ver determines when fired.
	 *
	 * Typeid 204 replace VLAN with groupid as VLAN ID and type_ver as QoS
	 * Typeid 205 replace VLAN 0 with typeid as VLAN ID
	 * Typeid 206 replace QoS 0 with type_ver as QoS
	 * Typeid 207 replace VLAN with groupid as VLAN ID
	 * For typeid 204-207 use upper nipple of type_ver as index into fid
	 * array.
	 *
	 * Typeid 208 replace all VLAN 0
	 * - with typeid as VLAN ID (filter format MAC/VID)
	 * - with group identifier as VLAN ID (filter format GROUP/[MAC/]VID)
	 * - use upper nibble of type_ver to indicate a QoS change (true),
	 *   lower nibble of type_ver is QoS value.
	 */
	switch (p->type_id) {
	case 199:
		if (called == p->type_ver) {
			rc = VDP22_RESP_TIMEOUT;
		}
		break;
	case 200:
		trigger_deassoc(p->vdp);
		break;
	case 201:
	case 203:
		if (called == p->type_ver) {
			*error = VDP22_RESP_NO_RESOURCES;
			rc = VDP22_RESP_DEASSOC;
			if (p->type_id == 203)
				*error |= 0x10;
		}
		break;
	case 202:
		if (called == p->type_ver) {
			*error = VDP22_RESP_NO_VSIMGR;
			rc = VDP22_RESP_KEEP;
		}
		break;
	case 204:
	case 205:
	case 206:
	case 207:
	case 208:
		*error = change_fid(p);
		if (*error == VDP22_RESP_NOADDR)
			rc = VDP22_RESP_DEASSOC;
		break;
	}
#endif
	LLDPAD_DBG("%s:%s resp_vsi_mode:%d rc:%d error:%d\n", __func__,
		   p->vdp->ifname, p->resp_vsi_mode, rc, *error);
	return rc;
}
