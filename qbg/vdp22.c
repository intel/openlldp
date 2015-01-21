/******************************************************************************

  Implementation of VDP22 protocol for IEEE 802.1 Qbg ratified standard
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <net/if.h>

#include "messages.h"
#include "config.h"

#include "lldp_mod.h"
#include "lldp_util.h"
#include "qbg_vdpnl.h"
#include "qbg22.h"
#include "qbg_vdp22.h"
#include "qbg_utils.h"
#include "qbg_vdp22_cmds.h"
#include "qbg_vdp22def.h"

#define INIT_FN(name) name##_oui_init
#define EXTERN_FN(name)\
extern bool name##_oui_init()

/* Init handlers for OUI. OUI handlers should be added in vdp22_oui_init_list.
 * First argument specifies the OUI code assigned to the Organization.
 * Second argument is the string which should match with the CLI and the third
 * argument is the init handler.
 */

struct vdp22_oui_init_s vdp22_oui_init_list[] = {
};

struct vdp22_oui_handler_s vdp22_oui_list[MAX_NUM_OUI];
unsigned char g_oui_index;

/*
 * VDP22 helper functions
 */

/*
 * Convert IPv4 address to string.
 */
int vdp22_ipv42str(const u8 *p, char *dst, size_t size)
{
	if (dst && size > VDP_UUID_STRLEN) {
		snprintf(dst, size, "%02x%02x:%02x%02x:%02x%02x",
			 p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}

/*
 * Convert IPv6 address to string.
 * TODO
 * - compression of 16 bits zero fields
 * - omit leading zeroes
 */
int vdp22_ipv62str(const u8 *p, char *dst, size_t size)
{
	if (dst && size > VDP_UUID_STRLEN) {
		snprintf(dst, size, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}

static int vdp22_local2str(const u8 *p, char *dst, size_t size)
{
	if (dst && size > VDP_UUID_STRLEN) {
		snprintf(dst, size, "%02x%02x%02x%02x%02x%02x%02x%02x"
			 "%02x%02x%02x%02x%02x%02x%02x%02x",
			 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}

/*
 * Print VSI filter information data.
 */
static void showvsifid(char *txt, unsigned char fif, unsigned short no,
		       struct fid22 *fe)
{
	char idbuf[VDP_UUID_STRLEN + 2];
	int i;

	for (i = 0; i < no; ++i, ++fe) {
		switch (fif) {
		case VDP22_FFMT_GROUPVID:
			LLDPAD_DBG("%s:grpid:%ld vlan:%d qos:%d"
				   " pid:%d seq:%ld\n", txt, fe->grpid,
				   vdp22_get_vlanid(fe->vlan),
				   vdp22_get_qos(fe->vlan),
				   fe->requestor.req_pid,
				   fe->requestor.req_seq);
			break;
		case VDP22_FFMT_GROUPMACVID:
			mac2str(fe->mac, idbuf, sizeof idbuf);
			LLDPAD_DBG("%s:mac:%s grpid:%ld vlan:%d"
				   " qos:%d pid:%d seq:%ld\n", txt, idbuf,
				   fe->grpid, vdp22_get_vlanid(fe->vlan),
				   vdp22_get_qos(fe->vlan),
				   fe->requestor.req_pid,
				   fe->requestor.req_seq);
			break;
		case VDP22_FFMT_VID:
			LLDPAD_DBG("%s:vlan:%d qos:%d pid:%d seq:%ld\n",
				   txt, vdp22_get_vlanid(fe->vlan),
				   vdp22_get_qos(fe->vlan),
				   fe->requestor.req_pid,
				   fe->requestor.req_seq);
			break;
		case VDP22_FFMT_MACVID:
			mac2str(fe->mac, idbuf, sizeof idbuf);
			LLDPAD_DBG("%s:mac:%s vlan:%d qos:%d"
				   " pid:%d seq:%ld\n", txt, idbuf,
				   vdp22_get_vlanid(fe->vlan),
				   vdp22_get_qos(fe->vlan),
				   fe->requestor.req_pid,
				   fe->requestor.req_seq);
			break;
		default:
			LLDPAD_DBG("%s:unsupported filter info format\n", txt);
		}
	}
}

/*
 * Convert a mgrid to a printable string.
 */
static void mgrid2str(struct vsi22 *p, char *buf, size_t len)
{
	int i, nul;
	bool print = false;

	/* Find last non nul byte */
	for (nul = sizeof(p->mgrid) - 1; nul >= 0; --nul) {
		if (p->mgrid[nul] != '\0')
			break;
	}
	if (nul == 0) {
		sprintf(buf, "%d", p->mgrid[0]);
		return;
	}
	for (i = 0; i <= nul; ++i) {
		if (isprint(p->mgrid[i]))
			print = true;
		else
			break;
	}
	if (print)
		strncpy(buf, (char *)p->mgrid, len);
	else
		vdp22_local2str(p->mgrid, buf, len);
}

/*
 * Print VSI data
 */
void vdp22_showvsi(struct vsi22 *p)
{
	char idbuf[VDP_UUID_STRLEN + 2];
	char mgridbuf[VDP_UUID_STRLEN + 2];

	switch (p->vsi_fmt) {
	case VDP22_ID_UUID:
		vdp_uuid2str(p->vsi, idbuf, sizeof(idbuf));
		break;
	case VDP22_ID_MAC:
		mac2str(p->vsi + 10, idbuf, sizeof(idbuf));
		break;
	case VDP22_ID_IP4:
		vdp22_ipv42str(p->vsi, idbuf, sizeof(idbuf));
		break;
	case VDP22_ID_IP6:
		vdp22_ipv62str(p->vsi, idbuf, sizeof(idbuf));
		break;
	case VDP22_ID_LOCAL:
		vdp22_local2str(p->vsi, idbuf, sizeof(idbuf));
		break;
	default:
		strcpy(idbuf, "unsupported format");
		break;
	}

	mgrid2str(p, mgridbuf, sizeof(mgridbuf));
	LLDPAD_DBG("vsi:%p flags:%#lx vsi_mode:%d,%d status:%#x"
		   " mgrid:%s id:%ld(%#lx) version:%d"
		   " id_fmt:%d %s format:%d no:%d\n",
		   p, p->flags, p->vsi_mode, p->cc_vsi_mode, p->status,
		   mgridbuf, p->type_id,
		   p->type_id, p->type_ver, p->vsi_fmt, idbuf,
		   p->fif, p->no_fdata);
	if (p->fdata)
		showvsifid("fid", p->fif, p->no_fdata, p->fdata);
	LLDPAD_DBG("smi:state:%d kato:%d ackreceived:%d acktimeout:%d"
		   " localchg:%d deassoc:%d txmit:%d resp_ok:%d"
		   " txmit_error:%d\n", p->smi.state, p->smi.kato,
		   p->smi.ackreceived, p->smi.acktimeout, p->smi.localchg,
		   p->smi.deassoc, p->smi.txmit, p->smi.resp_ok,
		   p->smi.txmit_error);
}

/*
 * Delete the OUI structures of VSI22
 * This calls the respective OUI handlers which are responsible for freeing
 * the OUI specific 'data' element of 'vdp22_oui_data_s' structure.
 */

static void vdp22_delete_oui(struct vsi22 *p)
{
	struct vdp22_oui_data_s *oui_str;
	struct vdp22_oui_handler_s *oui_hndlr;
	int idx;
	bool ret;

	if ((p->no_ouidata == 0) || (!p->oui_str_data))
		return;
	for (idx = 0; idx < p->no_ouidata; idx++) {
		oui_str = &p->oui_str_data[idx];
		oui_hndlr = vdp22_get_oui_hndlr(oui_str->oui_name);
		if (!oui_hndlr)
			LLDPAD_ERR("%s: Unknown OUI %s\n",
				   __func__, oui_str->oui_name);
		else {
			ret = oui_hndlr->vdp_free_oui_hndlr(oui_str);
			LLDPAD_DBG("%s: Free handler returned %d\n", __func__,
				   ret);
		}
	}
	free(p->oui_str_data);
}

/*
 * Delete a complete VSI node not on queue.
 */
void vdp22_delete_vsi(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	free(p->fdata);
	vdp22_delete_oui(p);
	free(p);
}

/*
 * Remove a VSI node from list and delete it.
 */
void vdp22_listdel_vsi(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	LIST_REMOVE(p, node);
	vdp22_delete_vsi(p);
}

/* Check for valid VSI request mode, filter info format and VSI ID */
/*
 * Return true if data consists completely of zeroes.
 */
static bool is_zeroes(unsigned char *cp, size_t len)
{
	size_t x;

	for (x = 0; x < len; ++x)
		if (*cp++)
			return false;
	return true;
}

/*
 * IPV4 address right aligned with leading zeros.
 */
static bool is_ipv4(unsigned char *cp)
{
	if (!is_zeroes(cp, 10))
		return false;
	if (cp[10] != 0xff && cp[11] != 0xff)
		return false;
	if (is_zeroes(cp + 12, 4))
		return false;
	return true;
}

/*
 * MAC address right aligned with leading zeros.
 */
static bool is_mac(unsigned char *cp)
{
	if (!is_zeroes(cp, 10))
		return false;
	return is_valid_mac(cp + 10);
}

/*
 * IPV6 address.
 */
static bool is_ipv6(unsigned char *cp)
{
	if (is_zeroes(cp, 16))
		return false;
	return true;
}

/*
 * Check if VSI request is valid.
 */
static bool check_vsirequest(unsigned char request)
{
	bool rc = true;

	switch (request) {
	case VDP22_PREASSOC:
	case VDP22_PREASSOC_WITH_RR:
	case VDP22_ASSOC:
	case VDP22_DEASSOC:
	case VDP22_MGRID:
	case VDP22_OUI:
		break;
	default:
		rc = false;
	}
	LLDPAD_DBG("%s rc:%d\n", __func__, rc);
	return rc;
}

/*
 * Check if VSI filter information format is valid.
 */
static bool check_filterfmt(unsigned char filter_fmt)
{
	bool rc = true;

	switch (filter_fmt) {
	case VDP22_FFMT_VID:
	case VDP22_FFMT_MACVID:
	case VDP22_FFMT_GROUPVID:
	case VDP22_FFMT_GROUPMACVID:
		break;
	default:
		rc = false;
	}
	LLDPAD_DBG("%s rc:%d\n", __func__, rc);
	return rc;
}

/*
 * Check if VSI identifier is valid.
 */
static bool check_vsiid(unsigned char fmt, unsigned char *vsi_uuid)
{
	bool rc = true;

	switch (fmt) {
	case VDP22_ID_IP4:
		if (!is_ipv4(vsi_uuid))
			rc = false;
		break;
	case VDP22_ID_IP6:
		if (!is_ipv6(vsi_uuid))
			rc = false;
		break;
	case VDP22_ID_MAC:
		if (!is_mac(vsi_uuid))
			rc = false;
		break;
	case VDP22_ID_UUID:
		if (is_zeroes(vsi_uuid, sizeof(vsi_uuid)))
			rc = false;
		break;
	case VDP22_ID_LOCAL:
		/* Anything goes */
		break;
	default:
		rc = false;
	}
	LLDPAD_DBG("%s rc:%d\n", __func__, rc);
	return rc;
}

/*
 * Check if VSI information received via netlink message is valid.
 */
static bool check_vsinl(struct vdpnl_vsi *vsi)
{
	bool rc;

	rc =  check_vsiid(vsi->vsi_idfmt, vsi->vsi_uuid)
		&& check_vsirequest(vsi->request)
		&& check_filterfmt(vsi->filter_fmt);
	LLDPAD_DBG("%s:%s request:%d filter_fmt:%d vsi_fmt:%d rc:%d\n",
		   __func__, vsi->ifname, vsi->request, vsi->filter_fmt,
		   vsi->vsi_idfmt, rc);
	return rc;
}

/*
 * Check if VSI information received via TLV message is valid.
 */
static bool check_vsi(struct vsi22 *vsi)
{
	bool rc;

	rc =  check_vsiid(vsi->vsi_fmt, vsi->vsi)
		&& check_vsirequest(vsi->vsi_mode) && check_filterfmt(vsi->fif);
	LLDPAD_DBG("%s:%s vsi_mode:%d filter_fmt:%d vsi_fmt:%d rc:%d\n",
		   __func__, vsi->vdp->ifname, vsi->vsi_mode, vsi->fif,
		   vsi->vsi_fmt, rc);
	return rc;
}

/*
 * Copy filter information data.
 */
static void copy_filter(unsigned char fif, struct fid22 *fp,
			struct vdpnl_mac *from)
{
	switch (fif) {
	case VDP22_FFMT_GROUPMACVID:
	case VDP22_FFMT_GROUPVID:
		fp->grpid = from->gpid;
		if (fif == VDP22_FFMT_GROUPVID)
			goto vid;
		/* Fall through intended */
	case VDP22_FFMT_MACVID:
		memcpy(fp->mac, from->mac, sizeof(fp->mac));
		/* Fall through intended */
	case VDP22_FFMT_VID:
vid:
		fp->vlan = vdp22_set_vlanid(from->vlan)
				| vdp22_set_qos(from->qos);
		break;
	}
}

/*
 * Check supplied filter information.
 */
static bool check_mac(struct fid22 *fp)
{
	if (!is_valid_mac(fp->mac))
		return false;
	return true;
}

static bool check_vid(struct fid22 *fp)
{
	unsigned short num = vdp22_get_vlanid(fp->vlan);

	if (num > 0 && (num < 2 || num > 4094))
		return false;
	return true;
}

static bool check_group(struct fid22 *fp)
{
	return fp->grpid ? true : false;
}

/*
 * Check for filter information consistency.
 */
static bool filter_ok(unsigned char ffmt, struct fid22 *fp,
		      unsigned char gpid_on)
{
	bool rc = false;

	switch (ffmt) {
	case VDP22_FFMT_VID:
		rc = check_vid(fp);
		break;
	case VDP22_FFMT_MACVID:
		rc = check_vid(fp) && check_mac(fp);
		break;
	case VDP22_FFMT_GROUPVID:
		if (gpid_on)
			rc = check_vid(fp) && check_group(fp);
		else
			rc = false;
		break;
	case VDP22_FFMT_GROUPMACVID:
		if (gpid_on)
			rc = check_vid(fp) && check_mac(fp) &&
				check_group(fp);
		else
			rc = false;
	}
	LLDPAD_DBG("%s: ffmt:%d gpid_on:%d rc:%d\n", __func__, ffmt,
		   gpid_on, rc);
	return rc;
}

static void vdpnl_alloc_vsi_oui(struct vdpnl_vsi *vsi, struct vsi22 *p)
{
	struct vdp22_oui_handler_s *oui_hndlr;
	bool ret;
	int idx;

	if (vsi->ouisz == 0)
		return;
	p->no_ouidata = vsi->ouisz;
	p->oui_str_data = calloc(vsi->ouisz, sizeof(struct vdp22_oui_data_s));
	if (!p->oui_str_data) {
		LLDPAD_ERR("%s: calloc return failure\n", __func__);
		return;
	}
	for (idx = 0; idx < vsi->ouisz; idx++) {
		struct vdpnl_oui_data_s *from = &vsi->oui_list[idx];
		struct vdp22_oui_data_s *to = &p->oui_str_data[idx];

		oui_hndlr = vdp22_get_oui_hndlr(from->oui_name);
		if (!oui_hndlr)
			LLDPAD_ERR("%s: Unknown OUI Name %s\n",
				   __func__, from->oui_name);
		else {
			ret = oui_hndlr->vdpnl2vsi22_hndlr(p, from, to);
			if (!ret)
				LLDPAD_ERR("%s: handler return error for "
					   "oui %s\n", __func__,
					   from->oui_name);
		}
	}
}

/*
 * Allocate a VSI node with filter information data.
 * Check if input data is valid.
 */
static struct vsi22 *vdp22_alloc_vsi_int(struct vdpnl_vsi *vsi,
					 struct vdp22 *vdp,
					 int *rc, bool vsinl_chk)
{
	struct vsi22 *p;
	int i;

	*rc = -EINVAL;
	if (vsinl_chk && (!check_vsinl(vsi)))
		return NULL;
	p = calloc(1, sizeof(*p));
	if (!p) {
		*rc = -ENOMEM;
		return p;
	}

	p->no_fdata = vsi->macsz;
	p->fdata = calloc(vsi->macsz, sizeof(struct fid22));
	if (!p->fdata) {
		free(p);
		*rc = -ENOMEM;
		return NULL;
	}

	p->vdp = vdp;
	p->vsi_mode = vsi->request;
	p->cc_vsi_mode = VDP22_DEASSOC;
	p->hints = vsi->hints;
	p->status = VDP22_RESP_NONE;
	p->flags = VDP22_BUSY | VDP22_NLCMD;
	if (vsi->nl_version == vdpnl_nlf2)
		memcpy(p->mgrid, vsi->vsi_mgrid2, sizeof(p->mgrid));
	else
		p->mgrid[0] = vsi->vsi_mgrid;
	p->type_ver = vsi->vsi_typeversion;
	p->type_id = vsi->vsi_typeid;
	p->vsi_fmt = VDP22_ID_UUID;
	memcpy(p->vsi, vsi->vsi_uuid, sizeof(p->vsi));
	p->fif = vsi->filter_fmt;

	/* Copy filter info and do some sanity checks based on format */
	for (i = 0; i < vsi->macsz; ++i) {
		struct vdpnl_mac *from = &vsi->maclist[i];
		struct fid22 *fp = &p->fdata[i];

		copy_filter(p->fif, fp, from);
		if (from->vlan == 0) {
			/* Only one filter member with null vlan id */
			if (vsi->macsz > 1 && p->fif == VDP22_FFMT_VID) {
				*rc = -EINVAL;
				goto error1;
			}
			p->flags |= VDP22_RETURN_VID;
		}
		if (!filter_ok(p->fif, fp, vdp->gpid)) {
			*rc = -EINVAL;
			goto error1;
		}
		fp->requestor.req_pid = vsi->req_pid;
		fp->requestor.req_seq = vsi->req_seq;
	}
	vdpnl_alloc_vsi_oui(vsi, p);
	*rc = 0;
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, vsi->ifname, p, p->vsi[0]);
	return p;
error1:
	vdp22_showvsi(p);
	vdp22_delete_vsi(p);
	return NULL;
}

struct vsi22 *vdp22_alloc_vsi_ext(struct vdpnl_vsi *vsinl, int *rc)
{
	struct vdp22 *vdp;

	vdp = vdp22_getvdp(vsinl->ifname);
	if (!vdp)
		return NULL;
	return vdp22_alloc_vsi_int(vsinl, vdp, rc, false);
}

/*
 * Allocate a VSI node with filter information data.
 * Check if input data is valid. Data was received by bridge from unknown
 * counterpart and might be invalid.
 */
struct vsi22 *vdp22_copy_vsi(struct vsi22 *old)
{
	struct vsi22 *p;
	int i;

	if (!check_vsi(old))
		return NULL;
	p = calloc(1, sizeof(*p));
	if (!p)
		return p;
	*p = *old;
	p->flags = 0;
	p->cc_vsi_mode = VDP22_DEASSOC;
	p->fdata = calloc(p->no_fdata, sizeof(struct fid22));
	if (!p->fdata)
		goto error1;

	/* Copy filter info and do some sanity checks based on format */
	for (i = 0; i < p->no_fdata; ++i) {
		p->fdata[i] = old->fdata[i];
		/* Only one filter member with wildcard vlan id */
		if (p->fdata[i].vlan == 0) {
			if (p->no_fdata > 1 && p->fif == VDP22_FFMT_VID)
				goto error1;
		}
		if (!filter_ok(p->fif, &p->fdata[i], p->vdp->gpid))
			goto error1;
	}
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	return p;
error1:
	vdp22_delete_vsi(p);
	return NULL;
}

/*
 * Find the vdp data associated with an interface.
 * Parameter 'ud' may be zero, then search for the module first.
 *
 * Return pointer or NULL if not found.
 */
static struct vdp22 *vdp22_findif(const char *ifname,
				  struct vdp22_user_data *ud)
{
	struct vdp22 *vdp = 0;

	if (!ud) {
		ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
		if (!ud)
			LLDPAD_DBG("%s:%s no VDP22 module\n", __func__,
				   ifname);
	}
	if (ud) {
		LIST_FOREACH(vdp, &ud->head, node)
			if (!strncmp(ifname, vdp->ifname, IFNAMSIZ))
				break;
	}
	return vdp;
}

/*
 * Update data exchanged via ECP protocol.
 * Returns true when data update succeeded.
 */
static int data_from_ecp(char *ifname, struct ecp22_to_ulp *ptr)
{
	int rc = -ENOENT;
	struct vdp22 *vdp;

	vdp = vdp22_findif(ifname, NULL);
	if (vdp) {
		memcpy(vdp->input, ptr->data, ptr->len);
		vdp->input_len = ptr->len;
		rc = vdp22_from_ecp22(vdp);
		LLDPAD_DBG("%s:%s rc:%d ", __func__, ifname, rc);
	}
	return rc;
}

/*
 * Update data exchanged via EVB protocol.
 * Calculate the various time out values based in input parameters.
 * See IEEE 802.1Qbg ratified standard 41.5.5.7 + 41.5.5.9
 * Returns true when data update succeeded.
 */
static int data_from_evb(char *ifname, struct evb22_to_vdp22 *ptr)
{
	int rc = -ENOENT;
	struct vdp22 *vdp;

	vdp = vdp22_findif(ifname, NULL);
	if (vdp) {
		vdp->ecp_retries = ptr->max_retry;
		vdp->ecp_rte = ptr->max_rte;
		vdp->vdp_rka = ptr->max_rka;
		vdp->vdp_rwd = ptr->max_rwd;
		vdp->gpid = ptr->gpid;
		vdp->evbon = ptr->evbon;
		LLDPAD_DBG("%s:%s rwd:%d rka:%d gpid:%d retry:%d rte:%d evb:%d\n",
			   __func__, ifname, ptr->max_rwd, ptr->max_rka,
			   ptr->gpid, ptr->max_retry, ptr->max_rte, ptr->evbon);
		rc = 0;
	}
	return rc;
}

/*
 * Handle notifications from other modules. Check if sender-id and data type
 * indicator match. Return false when data could not be delivered.
 */
static int vdp22_notify(int sender_id, char *ifname, void *data)
{
	struct qbg22_imm *qbg = (struct qbg22_imm *)data;

	LLDPAD_DBG("%s:%s sender-id:%#x data_type:%d\n", __func__, ifname,
		   sender_id, qbg->data_type);
	if (sender_id == LLDP_MOD_EVB22 && qbg->data_type == EVB22_TO_VDP22)
		return data_from_evb(ifname, &qbg->u.b);
	if (sender_id == LLDP_MOD_ECP22 && qbg->data_type == ECP22_TO_ULP)
		return data_from_ecp(ifname, &qbg->u.c);
	return 0;
}

/*
 * Remove a vdp22 element and delete the chain of active VSIs
 */
static void vdp22_free_elem(struct vdp22 *vdp)
{
	while (!LIST_EMPTY(&vdp->vsi22_que)) {
		struct vsi22 *p = LIST_FIRST(&vdp->vsi22_que);

		vdp22_listdel_vsi(p);
	}
	LIST_REMOVE(vdp, node);
	free(vdp);
}

/*
 * Disable the interface for VDP protocol support.
 */
void vdp22_stop(char *ifname)
{
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;
	struct vsi22 *vsi;

	LLDPAD_DBG("%s:%s stop vdp\n", __func__, ifname);
	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	if (!vud) {
		LLDPAD_ERR("%s:%s no VDP22 module\n", __func__, ifname);
		return;
	}
	vdp = vdp22_findif(ifname, vud);
	if (!vdp) {
		LLDPAD_ERR("%s:%s no VDP22 data\n", __func__, ifname);
		return;
	}

	LIST_FOREACH(vsi, &vdp->vsi22_que, node) {
		vdp22_stop_timers(vsi);
	}
}

/*
 * vdp22_create - create data structure and initialize vdp protocol
 * @ifname: interface for which the vdp protocol is initialized
 *
 * returns NULL on error and an pointer to the vdp22 structure on success.
 *
 * Finds the port to the interface name, sets up the receive handle for
 * incoming vdp frames and initializes the vdp rx and tx state machines.
 * To be called when a successful exchange of EVB TLVs has been
 * made and ECP protocols are supported by both sides.
 *
 * Read the role (station vs bridge) from the configuration file.
 */
static struct vdp22 *vdp22_create(const char *ifname,
				  struct vdp22_user_data *eud, int role)
{
	struct vdp22 *vdp;

	vdp = calloc(1, sizeof *vdp);
	if (!vdp) {
		LLDPAD_ERR("%s:%s unable to allocate vdp protocol\n", __func__,
			   ifname);
		return NULL;
	}
	strncpy(vdp->ifname, ifname, sizeof vdp->ifname);
	vdp->myrole = role;
	LIST_INIT(&vdp->vsi22_que);
	LIST_INSERT_HEAD(&eud->head, vdp, node);
	LLDPAD_DBG("%s:%s role:%d\n", __func__, ifname, role);
	return vdp;
}

/*
 * Query the supported VDP protocol on an interface.
 */
struct vdp22 *vdp22_getvdp(const char *ifname)
{
	struct vdp22 *vdp;

	vdp = vdp22_findif(ifname, NULL);
	LLDPAD_DBG("%s:%s vdp %p\n", __func__, ifname, vdp);
	return vdp;
}

int vdp22_query(const char *ifname)
{
	int rc = 0;

	if (vdp22_getvdp(ifname))
		rc = 1;
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, ifname, rc);
	return rc;
}

/*
 * Enable the interface for VDP protocol support.
 */
void vdp22_start(const char *ifname, int role)
{
	struct vdp22_user_data *vud;
	struct vdp22 *vdp;
	struct vsi22 *vsi;

	LLDPAD_DBG("%s:%s start vdp\n", __func__, ifname);
	vud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP22);
	if (!vud) {
		LLDPAD_ERR("%s:%s no VDP22 module\n", __func__, ifname);
		return;
	}
	vdp = vdp22_findif(ifname, vud);

	if (!vdp) {
		vdp = vdp22_create(ifname, vud, role);
	} else {
		LIST_FOREACH(vsi, &vdp->vsi22_que, node) {
			vsi->smi.localchg = true;
			vdp22_showvsi(vsi);
			vdp22_start_localchange_timer(vsi);
		}
	}
}

/*
 * Handle a VSI request from buddy.
 */
int vdp22_request(struct vdpnl_vsi *vsi, int clif)
{
	int rc;
	struct vsi22 *p;
	struct vdp22 *vdp;

	LLDPAD_DBG("%s:%s clif:%d\n", __func__, vsi->ifname, clif);
	vdp = vdp22_findif(vsi->ifname, NULL);
	if (vdp) {
		if (!vdp->evbon) {
			rc = -EPROTONOSUPPORT;
			goto out;
		}
		if (vdp->myrole == VDP22_BRIDGE) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		/* Adjust numbering for VDP 0.2 protocol from netlink */
		if (!clif)
			vsi->request += 1;
		p = vdp22_alloc_vsi_int(vsi, vdp, &rc, true);
		if (p) {
			rc = vdp22_addreq(p, vdp);
			if (rc)
				vdp22_delete_vsi(p);
		}
	} else
		rc = -ENODEV;
out:
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, vsi->ifname, rc);
	return rc;
}

/*
 * Remove all interface/agent specific vdp data.
 */
static void vdp22_free_data(struct vdp22_user_data *ud)
{
	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			struct vdp22 *vd = LIST_FIRST(&ud->head);

			vdp22_free_elem(vd);
		}
	}
}

void vdp22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		vdp22_free_data((struct vdp22_user_data *)mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s:done\n", __func__);
}

static int clnt(void *data, struct sockaddr_un *from, socklen_t fromlen,
		      char *ibuf, int ilen, char *rbuf, int rlen)
{
	return vdp22_clif_cmd(data, from, fromlen, ibuf, ilen, rbuf, rlen);
}

static const struct lldp_mod_ops vdp22_ops =  {
	.lldp_mod_register	= vdp22_register,
	.lldp_mod_unregister	= vdp22_unregister,
	.lldp_mod_notify	= vdp22_notify,
	.get_arg_handler	= vdp22_arg_handlers,
	.client_cmd		= clnt,
};

struct lldp_module *vdp22_register(void)
{
	struct lldp_module *mod;
	struct vdp22_user_data *ud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s: failed to malloc module data\n", __func__);
		return NULL;
	}
	ud = calloc(1, sizeof *ud);
	if (!ud) {
		free(mod);
		LLDPAD_ERR("%s failed to malloc module user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&ud->head);
	mod->id = LLDP_MOD_VDP22;
	mod->ops = &vdp22_ops;
	mod->data = ud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;
}

static void copy_fid(struct vdpnl_vsi *vsi, struct vsi22 *p)
{
	int i;

	vsi->maclist = calloc(p->no_fdata, sizeof(*vsi->maclist));
	if (!vsi->maclist)
		return;
	vsi->macsz = p->no_fdata;
	vsi->filter_fmt = p->fif;
	for (i = 0; i < p->no_fdata; ++i) {
		vsi->maclist[i].gpid = p->fdata[i].grpid;
		vsi->maclist[i].vlan = vdp22_get_vlanid(p->fdata[i].vlan);
		vsi->maclist[i].qos = vdp22_get_qos(p->fdata[i].vlan);
		vsi->maclist[i].changed = 1;
		memcpy(vsi->maclist[i].mac, p->fdata[i].mac,
		       sizeof(vsi->maclist[i].mac));
	}
}

/*
 * Fill the VSI data to return to caller. Currently returned data depends
 * on requestor:
 * 1. Via netlink message from libvirtd and vdptest:
 *    Return UUID, Response when available. changed FID.
 * 2. Via lldptool:
 *    All data.
 */
static void copy_vsi(struct vdpnl_vsi *vsi, struct vsi22 *p, int clif)
{
	/* For netlink reply */
	vsi->response = p->status;
	memcpy(vsi->vsi_uuid, p->vsi, sizeof(vsi->vsi_uuid));
	/* For client interface reply */
	vsi->request = p->vsi_mode;
	vsi->vsi_typeid = p->type_id;
	vsi->vsi_typeversion = p->type_ver;
	memcpy(vsi->vsi_mgrid2, p->mgrid, sizeof(vsi->vsi_mgrid2));
	vsi->vsi_idfmt = p->vsi_fmt;
	vsi->hints = p->cc_vsi_mode;
	p->flags &= ~VDP22_NLCMD;
	if (clif || (p->flags & VDP22_RETURN_VID)) {
		copy_fid(vsi, p);
		p->flags &= ~VDP22_RETURN_VID;
	}
}

/*
 * Query a VSI request from buddy and report its progress. Use the interface
 * name to determine the VSI profile list. Return one entry in parameter 'vsi'
 * use the structure members response and vsi_uuid.
 * Returns
 * 1  valid VSI data returned
 * 0  end of queue (no VSI data returned)
 * <0 errno
 */
int vdp22_status(int number, struct vdpnl_vsi *vsi, int clif)
{
	struct vdp22 *vdp;
	struct vsi22 *p;
	int i = 0, ret = 0;

	LLDPAD_DBG("%s:%s clif:%d\n", __func__, vsi->ifname, clif);
	vdp = vdp22_findif(vsi->ifname, NULL);
	if (!vdp) {
		LLDPAD_ERR("%s:%s has not yet been configured\n", __func__,
			   vsi->ifname);
		return -ENODEV;
	}
	/* Iterate to queue element number */
	LIST_FOREACH(p, &vdp->vsi22_que, node) {
		if (++i == number) {
			ret = 1;
			break;
		}
	}
	if (ret) {
		vdp22_showvsi(p);
		copy_vsi(vsi, p, clif);
		if (vsi->response != VDP22_RESP_NONE &&
		    (p->flags & VDP22_DELETE_ME))
			vdp22_listdel_vsi(p);
	}
	LLDPAD_DBG("%s:%s entry:%d more:%d\n", __func__, vsi->ifname,
		   number, ret);
	return ret;
}

/*
 * Find out if vsi command was received via netlink interface or via
 * attached control interface. Pid equals zero means control interface.
 */
static pid_t havepid(struct vsi22 *vsi)
{
	pid_t mypid = 0;
	int i;

	for (i = 0; i < vsi->no_fdata; ++i)
		mypid = vsi->fdata[i].requestor.req_pid;
	return mypid;
}

unsigned char vdp22_getsm_errcode(struct vsi22 *vsi)
{
	unsigned char err_code = 0;

	if (vsi->smi.kato)
		err_code |= (1 << VDP22_KATO);
	if (vsi->smi.acktimeout)
		err_code |= (1 << VDP22_ACKTO);
	if (vsi->smi.txmit_error)
		err_code |= (1 << VDP22_TXERR);
	return err_code;
}

/*
 * Convert and VSI22 to VDP netlink format and send it back to the originator.
 */
static int vdp22_back(struct vsi22 *vsi, pid_t to,
		      int (*fct)(struct vdpnl_vsi *))
{
	unsigned char err_code;
	int i;
	struct vdpnl_vsi nl;
	struct vdpnl_mac nlmac[vsi->no_fdata];

	LLDPAD_DBG("%s:%s to:%d\n", __func__, vsi->vdp->ifname, to);
	memset(&nl, 0, sizeof(nl));
	memset(nlmac, 0, sizeof(nlmac));
	nl.maclist = nlmac;
	nl.macsz = vsi->no_fdata;
	memcpy(nl.ifname, vsi->vdp->ifname, sizeof(nl.ifname));
	nl.request = vsi->vsi_mode;
	nl.response = vsi->status;
	err_code = vdp22_getsm_errcode(vsi);
	nl.response |= (err_code << VDP22_STATUS_BITS);
	nl.vsi_mgrid = vsi->mgrid[0];
	memcpy(nl.vsi_mgrid2, vsi->mgrid, sizeof(nl.vsi_mgrid2));
	nl.vsi_typeversion = vsi->type_ver;
	nl.vsi_typeid = vsi->type_id;
	nl.vsi_idfmt = VDP22_ID_UUID;
	memcpy(nl.vsi_uuid, vsi->vsi, sizeof(nl.vsi_uuid));
	nl.filter_fmt = vsi->fif;
	for (i = 0; i < nl.macsz; ++i) {
		nlmac[i].vlan = vdp22_get_vlanid(vsi->fdata[i].vlan);
		nlmac[i].qos = vdp22_get_qos(vsi->fdata[i].vlan);
		memcpy(nlmac[i].mac, vsi->fdata[i].mac, sizeof(nlmac[i].mac));
		nl.req_pid = vsi->fdata[i].requestor.req_pid;
		nl.req_seq = vsi->fdata[i].requestor.req_seq;
	}
	if (to)
		nl.request -= 1;		/* Maintain old number */
	(*fct)(&nl);
	if (vsi->flags & VDP22_DELETE_ME)
		vdp22_listdel_vsi(vsi);
	return 0;
}

/*
 * Send information back to netlink clients. When command was received via
 * control interface do not send back anything.
 */
int vdp22_nlback(struct vsi22 *vsi)
{
	pid_t nl_pid = havepid(vsi);

	LLDPAD_DBG("%s:%s vsi:%p(%#2x) nl_pid:%d\n", __func__, vsi->vdp->ifname,
		   vsi, vsi->vsi[0], nl_pid);
	return (nl_pid) ? vdp22_back(vsi, nl_pid, vdpnl_send) : 0;
}

/*
 * Send information back to attached clients. When command was received via
 * netlink message do not send back anything.
 */
int vdp22_clntback(struct vsi22 *vsi)
{
	pid_t nl_pid = havepid(vsi);

	LLDPAD_DBG("%s:%s vsi:%p(%#2x) nl_pid:%d\n", __func__, vsi->vdp->ifname,
		   vsi, vsi->vsi[0], nl_pid);
	return (!nl_pid) ? vdp22_back(vsi, 0, vdp22_sendevent) : 0;
}

/*
 * Query role. Return error when interface not available or interface is
 * running in bridge mode.
 */
int vdp22_info(const char *ifname)
{
	int rc = 0;
	struct vdp22 *vdp = vdp22_findif(ifname, NULL);

	if (!vdp)
		rc = -ENODEV;
	else if (vdp->myrole == VDP22_BRIDGE)
		rc = -EOPNOTSUPP;
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, ifname, rc);
	return rc;

}

void copy_vsi_external(struct vdpnl_vsi *vsi, struct vsi22 *p, int clif)
{
	copy_vsi(vsi, p, clif);
}

/*
 * This is called by the ORG specific code to register its handlers.
 */

bool oui_vdp_hndlr_init(struct vdp22_oui_handler_s *handler_ptr)
{
	if (!handler_ptr) {
		LLDPAD_DBG("%s: NULL handler\n", __func__);
		return false;
	}
	memcpy(&(vdp22_oui_list[g_oui_index]), handler_ptr,
		sizeof(vdp22_oui_list[g_oui_index]));
	g_oui_index++;
	return true;
}

/*
 * This calls the ORG specific init function. Then the ORG specific init
 * function registers its handlers.
 */

static void vdp22_oui_init(char *oui_name)
{
	int total;
	int idx;

	total = sizeof(vdp22_oui_init_list) / sizeof(vdp22_oui_init_list[0]);
	for (idx = 0; idx < total; idx++) {
		if (!strncmp(vdp22_oui_init_list[idx].oui_name, oui_name,
			     sizeof(vdp22_oui_init_list[idx].oui_name))) {
			if (!vdp22_oui_init_list[idx].oui_init())
				LLDPAD_ERR("%s: oui init return error for OUI "
					   "%s\n", __func__, oui_name);
		}
	}
}

static struct vdp22_oui_handler_s *get_oui_hndlr_internal(char *oui_name)
{
	int total;
	int idx;

	total = g_oui_index;
	for (idx = 0; idx < total; idx++) {
		if (!strncmp(vdp22_oui_list[idx].oui_name, oui_name,
			     sizeof(vdp22_oui_list[idx].oui_name)))
			return &vdp22_oui_list[idx];
	}
	return NULL;
}

/*
 * Return the handler structure associated with this OUI.
 * If the handler is already registered, then get_oui_hndlr_internal function
 * will return it. Otherwise, vdp22_oui_init is called so that the handler
 * init function is called which will register its handlers. This is done so
 * that the ORG specific handlers are registered only on demand.
 */

struct vdp22_oui_handler_s *vdp22_get_oui_hndlr(char *oui_name)
{
	struct vdp22_oui_handler_s *hndlr;

	if (oui_name == NULL) {
		LLDPAD_ERR("%s: NULL arg\n", __func__);
		return NULL;
	}
	/*
	 * First check if the handler exists.
	 * If not the OUI plugin is probably not initialized
	 * Initialize the handlers
	 */
	hndlr = get_oui_hndlr_internal(oui_name);
	if (hndlr != NULL)
		return hndlr;
	vdp22_oui_init(oui_name);
	return get_oui_hndlr_internal(oui_name);
}
