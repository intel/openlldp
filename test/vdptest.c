/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2012

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
 * Test Program for lldpad to create and delete VSI profiles.
 * Send and receive netlink messages to lldpad to
 * - associate a VSI
 * - disassociate a VSI
 * - receive a netlink message from lldpad when
 *    - the switch de-associates the VSI profile (switch data base cleaned)
 *
 * Note:
 * libvirtd is currently the only production code user of lldpad netlink
 * interface. It uses
 * - no qos: always set to 0.
 * - only one mac/macvlan pair.
 * - netlink message format 1 (no qos/vlanid change on switch side, no group
 *   id support at all)
 *
 * Netlink message format 1 is the default and does not
 * - expect vlanid etc back from switch
 * - use the vsi.maclist.qos member at all.
 *
 * Netlink message format 2 is selected when
 * - group id is entered in the map keyword
 * - 2mgrid is selected as keyword to specified long manager identifier
 * - replacement vlan identifier is specified in the map keyword
 * - hints keyword is specified.
 * This format handles a reply from the switch and compares returned vlan/qos
 * values.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <stdbool.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <netlink/msg.h>

#include "clif.h"
#include "clif_msgs.h"
#include "include/qbg22.h"
#include "qbg_vdp22def.h"
#include "qbg_vdpnl.h"

#define	COPY_OP		"new="
#define	KEYLEN		16
#define CMD_ASSOC	'a'	/* Association */
#define CMD_DEASSOC	'd'	/* DE-Association */
#define CMD_PREASSOC	'p'	/* pre-Association */
#define CMD_RRPREASSOC	'r'	/* pre-Association with RR */
#define CMD_SLEEP	's'	/* Wait some time */
#define CMD_GETMSG	'g'	/* Receive messages */
#define CMD_ECHO	'e'	/* ECHO command */
#define CMD_EXTERN	'E'	/* External command */
#define CMD_SETDF	'X'	/* Change defaults */

#define	BAD_FILTER	250	/* VLAN error in filter data */

#define	DIM(x)			(sizeof(x)/sizeof(x[0]))

/*
 * New version, implemented as library function and header file in lldpad-devel
 * package.
 *
 * Netlink message for QBG 2.2 ratified standard
 */

enum {					/* 802.1Qbg VDP ratified standard */
	IFLA_PORT_VSI_TYPE22 = IFLA_PORT_MAX,
	IFLA_PORT_VSI_FILTER,
	__IFLA_PORT_MAX_NEW
};

#undef	IFLA_PORT_MAX
#define IFLA_PORT_MAX (__IFLA_PORT_MAX_NEW - 1)

/*
 * Filter information data. Valid fields are determined by the
 * filter information format type member named  'vsi_filter_fmt'. The
 * number of the entries available is stored in the member named
 * 'vsi_filter_num', see below.
 */
struct ifla_port_vsi_filter {
	__u32 gpid;			/* Group Identifier*/
	__u16 vlanid;			/* Vlan id and QoS */
	__u8 mac[6];			/* MAC address */
};

struct ifla_port_vsi22 {		/* 802.1 Qbg Ratified standard */
	__u8 vsi_mgrid[PORT_UUID_MAX];	/* Manager identifier */
	__u8 vsi_uuid[PORT_UUID_MAX];	/* VSI identifier */
	__u8 vsi_uuidfmt;		/* Format of UUID string */
	__u8 vsi_type_id[3];		/* Type identifier */
	__u8 vsi_type_version;		/* Type version identifier */
	__u8 vsi_hints;			/* Hint bits */
	__u8 vsi_filter_fmt;		/* Filter information format */
	__u16 vsi_filter_num;		/* # of filter data entries */
};

/*
 * Helper functions to construct a netlink message.
 * The functions assume the nlmsghdr.nlmsg_len is set correctly.
 */
static void mynla_nest_end(struct nlmsghdr *nlh, struct nlattr *start)
{
	start->nla_type |= NLA_F_NESTED;
	start->nla_len = (void *)nlh + nlh->nlmsg_len - (void *)start;
}

static struct nlattr *mynla_nest_start(struct nlmsghdr *nlh, int type)
{
	struct nlattr *ap = (struct nlattr *)((void *)nlh + nlh->nlmsg_len);

	ap->nla_type = type;
	nlh->nlmsg_len += NLA_HDRLEN;
	return ap;
}

static void mynla_put(struct nlmsghdr *nlh, int type, size_t len, void *data)
{
	struct nlattr *ap = (struct nlattr *)((void *)nlh + nlh->nlmsg_len);

	ap->nla_type = type;
	ap->nla_len = NLA_HDRLEN + len;
	memcpy(ap + 1, data, len);
	nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(len);
}

static void mynla_put_u8(struct nlmsghdr *nlh, int type, __u8 data)
{
	mynla_put(nlh, type, sizeof data, &data);
}

static void mynla_put_u32(struct nlmsghdr *nlh, int type, __u32 data)
{
	mynla_put(nlh, type, sizeof data, &data);
}

static void *mynla_data(const struct nlattr *nla)
{
	return (char *)nla + NLA_HDRLEN;
}

static void mynla_get(const struct nlattr *nla, size_t len, void *data)
{
	memcpy(data, mynla_data(nla), len);
}

static __u32 mynla_get_u32(const struct nlattr *nla)
{
	return *(__u32 *)mynla_data(nla);
}

static __u16 mynla_get_u16(const struct nlattr *nla)
{
	return *(__u16 *)mynla_data(nla);
}

static int mynla_payload(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

static int mynla_type(const struct nlattr *nla)
{
	return nla->nla_type & ~NLA_F_NESTED;
}

static int mynla_ok(const struct nlattr *nla, int rest)
{
	return rest >= (int) sizeof(*nla) &&
	       nla->nla_len >= sizeof(*nla) && nla->nla_len <= rest;
}

static struct nlattr *mynla_next(const struct nlattr *nla, int *rest)
{
	int len = NLA_ALIGN(nla->nla_len);

	*rest -= len;
	return (struct nlattr *)((char *)nla + len);
}

static inline int mynla_attr_size(int payload)
{
	return NLA_HDRLEN + payload;
}

static int mynla_total_size(int payload)
{
	return NLA_ALIGN(mynla_attr_size(payload));
}

/*
 * Parse a list of netlink attributes.
 * Return 0 on success and errno when the parsing fails.
 */
static int mynla_parse(struct nlattr **tb, size_t tb_len, struct nlattr *pos,
		       int attrlen)
{
	unsigned short nla_type;

	while (mynla_ok(pos, attrlen)) {
		nla_type = mynla_type(pos);
		if (nla_type < tb_len)
			tb[nla_type] = (struct nlattr *)pos;
		pos = mynla_next(pos, &attrlen);
	}
	return (attrlen) ? -EINVAL : 0;
}


/*
 * Return needed buffer space in bytes to construct netlink message setlink
 * request. Return the maximum size needed.
 * In netlink message format 1 only one MAC/VLAN pair is supported.
 * In netlink message format 2 many MAC/VLAN/group pairs are supported.
 */
static size_t nlvsi_getsize(struct vdpnl_vsi *vsip)
{
	return NLMSG_SPACE(sizeof(struct ifinfomsg))	/* Header */
		+ mynla_total_size(IFNAMSIZ + 1)	/* IFLA_IFNAME */
		+ mynla_total_size(sizeof(struct nlattr)) /* IFLA_VF_PORTS */
		+ mynla_total_size(4)		/* VF_PORTS */
		+ mynla_total_size(4)		/* VF_PORT */
		+ mynla_total_size(1)		/* PORT_VDP_REQUEST */
		+ mynla_total_size(2)		/* PORT_VDP_RESPONSE */
		+ mynla_total_size(PORT_UUID_MAX)	/* INSTANCE UUID */
		+ mynla_total_size(sizeof(struct ifla_port_vsi))
						/* VSI_TYPE */
		+ mynla_total_size(sizeof(struct nlattr))
						/* IFLA_VFINFO_LIST */
		+ mynla_total_size(sizeof(struct nlattr))
						/* IFLA_VF_INFO */
		+ mynla_total_size(sizeof(struct ifla_vf_mac))
						/* IFLA_VF_MAC */
		+ mynla_total_size(sizeof(struct ifla_vf_vlan ))
						/* IFLA_VF_VLAN */
		+ mynla_total_size(sizeof(struct ifla_port_vsi22))
		+ mynla_total_size(vsip->macsz
					* sizeof(struct ifla_port_vsi_filter));
}

/*
 * Test input and return false on error.
 */
static int nlvsi_isgood(struct vdpnl_vsi *vsip)
{
	if (!vsip->macsz)
		return 0;
	switch (vsip->filter_fmt) {
	case VDP22_FFMT_MACVID:
	case VDP22_FFMT_VID:
	case VDP22_FFMT_GROUPMACVID:
	case VDP22_FFMT_GROUPVID:
		break;
	default:
		return 0;
	}

	/*
	 * Adjust for different request numbering.
	 * Draft 0.2 starts from 0 and ratified standard starts from 1.
	 * Sequence is PREASSOC, PREASSOC_RR, ASSOC, DEASSOC
	 *
	 * Expect "offical" draft 0.2 numbering defined in
	 * /usr/include/linux/if_link.h
	 */
	switch (vsip->request + 1) {
	case VDP22_PREASSOC:
	case VDP22_PREASSOC_WITH_RR:
	case VDP22_ASSOC:
	case VDP22_DEASSOC:
		break;
	default:
		return 0;
	}

	switch (vsip->vsi_idfmt) {
	case VDP22_ID_IP4:
	case VDP22_ID_IP6:
	case VDP22_ID_MAC:
	case VDP22_ID_LOCAL:
	case VDP22_ID_UUID:
		break;
	default:
		return 0;
	}

	if (vsip->hints && (vsip->hints != VDP22_MIGTO
	    && vsip->hints != VDP22_MIGFROM))
		return 0;

	if (vsip->vsi_typeid >= (1 << 24))	/* 3 byte type identifier */
		return 0;
	return 1;
}

/*
 * Build netlink message 1 format.
 */
static void nlf1(struct vdpnl_vsi *vsip, struct nlmsghdr *nlh)
{
	struct nlattr *port, *ports;
	struct ifla_port_vsi myvsi;
	int i;

	ports = mynla_nest_start(nlh, IFLA_VF_PORTS);
	port = mynla_nest_start(nlh, IFLA_VF_PORT);
	mynla_put_u8(nlh, IFLA_PORT_REQUEST, vsip->request);
	memset(&myvsi, 0, sizeof(myvsi));
	myvsi.vsi_mgr_id = vsip->vsi_mgrid;
	myvsi.vsi_type_id[2] = (vsip->vsi_typeid >> 16) & 0xff;
	myvsi.vsi_type_id[1] = (vsip->vsi_typeid >> 8) & 0xff;
	myvsi.vsi_type_id[0] = vsip->vsi_typeid & 0xff;
	myvsi.vsi_type_version = vsip->vsi_typeversion;
	mynla_put(nlh, IFLA_PORT_VSI_TYPE, sizeof(myvsi), &myvsi);
	mynla_put(nlh, IFLA_PORT_INSTANCE_UUID, PORT_UUID_MAX, vsip->vsi_uuid);
	mynla_nest_end(nlh, port);
	mynla_nest_end(nlh, ports);

	ports = mynla_nest_start(nlh, IFLA_VFINFO_LIST);
	for (i = 0; i < vsip->macsz; ++i) {
		port = mynla_nest_start(nlh, IFLA_VF_INFO);
		if (vsip->filter_fmt == VDP22_FFMT_MACVID) {
			struct ifla_vf_mac vf_mac = {
				.vf = PORT_SELF_VF
			};

			memcpy(vf_mac.mac, vsip->maclist[i].mac, ETH_ALEN);
			mynla_put(nlh, IFLA_VF_MAC, sizeof(vf_mac), &vf_mac);
		}
		if (vsip->filter_fmt) {
			struct ifla_vf_vlan vf_vlan = {
				.vf = PORT_SELF_VF,
				.vlan = vsip->maclist[i].vlan & 0xfff,
				.qos = (vsip->maclist[i].vlan >> 12) & 7
			};

			mynla_put(nlh, IFLA_VF_VLAN, sizeof(vf_vlan), &vf_vlan);
		}
		mynla_nest_end(nlh, port);
	}
	mynla_nest_end(nlh, ports);
}

/*
 * Build netlink message 2 format.
 */
static void nlf2(struct vdpnl_vsi *vsip, struct nlmsghdr *nlh)
{
	struct ifla_port_vsi22 myvsi;
	struct ifla_port_vsi_filter fdata[vsip->macsz];
	struct nlattr *port, *ports;
	int i;

	memset(&myvsi, 0, sizeof(myvsi));
	memset(fdata, 0, sizeof(fdata));
	ports = mynla_nest_start(nlh, IFLA_VF_PORTS);
	port = mynla_nest_start(nlh, IFLA_VF_PORT);
	mynla_put_u32(nlh, IFLA_PORT_VF, vsip->vf);
	mynla_put_u8(nlh, IFLA_PORT_REQUEST, vsip->request);
	mynla_put(nlh, IFLA_PORT_INSTANCE_UUID, PORT_UUID_MAX, vsip->vsi_uuid);
	myvsi.vsi_type_id[2] = (vsip->vsi_typeid >> 16) & 0xff;
	myvsi.vsi_type_id[1] = (vsip->vsi_typeid >> 8) & 0xff;
	myvsi.vsi_type_id[0] = vsip->vsi_typeid & 0xff;
	myvsi.vsi_type_version = vsip->vsi_typeversion;
	myvsi.vsi_uuidfmt = vsip->vsi_idfmt;
	memcpy(myvsi.vsi_mgrid, vsip->vsi_mgrid2, sizeof(myvsi.vsi_mgrid));
	myvsi.vsi_hints = vsip->hints;
	myvsi.vsi_filter_fmt = vsip->filter_fmt;
	myvsi.vsi_filter_num = vsip->macsz;
	mynla_put(nlh, IFLA_PORT_VSI_TYPE22, sizeof(myvsi), &myvsi);
	for (i = 0; i < vsip->macsz; ++i) {
		struct ifla_port_vsi_filter *ep = &fdata[i];

		ep->vlanid = vsip->maclist[i].vlan;
		if (vsip->filter_fmt == VDP22_FFMT_MACVID
		    || vsip->filter_fmt == VDP22_FFMT_GROUPMACVID)
			memcpy(ep->mac, vsip->maclist[i].mac, sizeof(ep->mac));
		if (vsip->filter_fmt == VDP22_FFMT_GROUPVID
		    || vsip->filter_fmt == VDP22_FFMT_GROUPMACVID)
			ep->gpid = vsip->maclist[i].gpid;
	}
	mynla_put(nlh, IFLA_PORT_VSI_FILTER, sizeof(fdata), fdata);
	mynla_nest_end(nlh, port);
	mynla_nest_end(nlh, ports);
}

/*
 * Construct the netlink request message for the VSI profile.
 * Return number of bytes occupied in buffer or errno on error.
 */
static int vdpnl_request_build(struct vdpnl_vsi *vsip, unsigned char *buf,
			       size_t len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct ifinfomsg ifinfo;

	if (!nlvsi_isgood(vsip))
		return -EINVAL;
	if (nlvsi_getsize(vsip) > len)
		return -ENOMEM;
	memset(buf, 0, len);
	memset(&ifinfo, 0, sizeof(ifinfo));
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_seq = vsip->req_seq;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_len = NLMSG_SPACE(sizeof ifinfo);
	ifinfo.ifi_index = vsip->ifindex;
	ifinfo.ifi_family = AF_UNSPEC;
	memcpy(NLMSG_DATA(nlh), &ifinfo, sizeof(ifinfo));
	mynla_put(nlh, IFLA_IFNAME, 1 + strlen(vsip->ifname), vsip->ifname);
	if (vsip->nl_version == vdpnl_nlf2)
		nlf2(vsip, nlh);
	else
		nlf1(vsip, nlh);
	return nlh->nlmsg_len;
}

/*
 * Read the contents of the IFLA_PORT_VSI_FILTER netlink attribute.
 * It is an array of struct ifla_port_vsi_filter entries.
 * Return 0 on success and errno on failure.
 *
 * Code to parse netlink message format 2.
 */
static void parse_filter_data(struct vdpnl_vsi *vsip, struct nlattr *tb)
{
	int i = 0;
	struct ifla_port_vsi_filter elem[vsip->macsz];

	mynla_get(tb, sizeof(elem), elem);
	for (i = 0; i < vsip->macsz; ++i) {
		struct vdpnl_mac *macp = &vsip->maclist[i];
		struct ifla_port_vsi_filter *ep = &elem[i];

		macp->vlan = ep->vlanid;
		macp->gpid = ep->gpid;
		memcpy(macp->mac, ep->mac, sizeof(macp->mac));
	}
}

/*
 * Read the contents of the IFLA_PORT_VSI_FILTER netlink attribute.
 * Return 0 on success and errno on failure.
 *
 * Code to parse netlink message format 2.
 */
static int parse_vsi_type22(struct vdpnl_vsi *vsip, struct nlattr *tb,
			    struct nlattr *tc)
{
	struct ifla_port_vsi22 myvsi;

	mynla_get(tb, sizeof(myvsi), &myvsi);
	vsip->filter_fmt = myvsi.vsi_filter_fmt;
	if (vsip->macsz >= myvsi.vsi_filter_num) {
		vsip->macsz = myvsi.vsi_filter_num;
		parse_filter_data(vsip, tc);
		return 0;
	}
	return -E2BIG;
}

/*
 * Parse the IFLA_VF_PORT block of the netlink message.
 * Return 1 when uuid found and 0 when not found and errno else.
 * Set length of filter pair on return.
 *
 * Code to parse netlink message format 1.
 */
static int scan_vf_port(struct vdpnl_vsi *vsi, struct nlattr *tb)
{
	struct nlattr *vf[IFLA_PORT_MAX + 1];
	int found = 0, rc;

	memset(vf, 0, sizeof(vf));
	rc = mynla_parse(vf, DIM(vf), mynla_data(tb), mynla_payload(tb));
	if (rc)
		return -EINVAL;
	if (vf[IFLA_PORT_INSTANCE_UUID]) {
		if (!memcmp(mynla_data(vf[IFLA_PORT_INSTANCE_UUID]),
			    vsi->vsi_uuid, sizeof(vsi->vsi_uuid))
		     && vf[IFLA_PORT_RESPONSE]) {
			found = 1;
			vsi->response = mynla_get_u16(vf[IFLA_PORT_RESPONSE]);
		}
	} else
		return -EINVAL;
	if (found && vf[IFLA_PORT_VSI_TYPE22] && vf[IFLA_PORT_VSI_FILTER])
		rc = parse_vsi_type22(vsi, vf[IFLA_PORT_VSI_TYPE22],
				      vf[IFLA_PORT_VSI_FILTER]);
	else
		vsi->macsz = 0;
	return found;
}

/*
 * Parse the IFLA_VF_PORTS block of the netlink message. Expect many
 * IFLA_VF_PORT attribute and search the one we are looking for.
 * Return zero on success and errno else.
 *
 * Code to parse netlink message format 1.
 */
static int scan_vf_ports(struct vdpnl_vsi *vsi, struct nlattr *tb)
{
	struct nlattr *pos;
	int rest, rc = 0;

	for (rest = mynla_payload(tb), pos = mynla_data(tb);
		mynla_ok(pos, rest) && rc == 0; pos = mynla_next(pos, &rest)) {
		if (mynla_type(pos) == IFLA_VF_PORT)
			rc = scan_vf_port(vsi, pos);
		else
			rc = -EINVAL;
	}
	return rc;
}

/*
 * Scan the GETLINK reply and parse the response for the UUID.
 *
 * Return
 * < 0 on error
 * 0 wanted UUID not in reply
 * 1 found
 */
static int vdpnl_getreply_parse(struct vdpnl_vsi *p, unsigned char *buf,
		size_t len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *tb[IFLA_MAX + 1];
	int rc;

	if (len < nlh->nlmsg_len)
		return -ENOMEM;
	memset(tb, 0, sizeof(tb));
	rc = mynla_parse(tb, DIM(tb),
			 (struct nlattr *)IFLA_RTA(NLMSG_DATA(nlh)),
			 IFLA_PAYLOAD(nlh));
	if (rc || !tb[IFLA_VF_PORTS])
		return -EINVAL;
	return scan_vf_ports(p, tb[IFLA_VF_PORTS]);
}

/*
 * Parse a received netlink request message and check for errors.
 * When a netlink error message is received, return it in the 3rd
 * parameter.
 *
 * Return
 * <0 on parse error.
 * 1 when a netlink error response is received.
 * 0 when no netlink error response
 */
static int vdpnl_getreply_error(unsigned char *buf, size_t len, int *error)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	if (len < nlh->nlmsg_len)
		return -ENOMEM;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);

		if (error)
			*error = err->error;
		return 1;
	}
	return 0;
}

/*
 * Parse the IFLA_VF_PORT block of an unsolicited netlink message triggered
 * after a dis-associated from switch.
 * Set length of filter pair on return.
 *
 * Code to parse netlink message format 1.
 */
static int trigger_vf_port(struct vdpnl_vsi *vsi, struct nlattr *tb)
{
	struct nlattr *vf[IFLA_PORT_MAX + 1];
	int rc;
	struct ifla_port_vsi portvsi;

	memset(vf, 0, sizeof(vf));
	rc = mynla_parse(vf, DIM(vf), mynla_data(tb), mynla_payload(tb));
	if (rc)
		return -EINVAL;
	if (vf[IFLA_PORT_INSTANCE_UUID])
		mynla_get(vf[IFLA_PORT_INSTANCE_UUID], sizeof(vsi->vsi_uuid),
			  vsi->vsi_uuid);
	else
		return -EINVAL;
	if (vf[IFLA_PORT_REQUEST])
		vsi->response = mynla_get_u16(vf[IFLA_PORT_REQUEST]);
	else
		return -EINVAL;
	if (vf[IFLA_PORT_VF])
		vsi->vf = mynla_get_u32(vf[IFLA_PORT_VF]);
	else
		return -EINVAL;
	if (vf[IFLA_PORT_VSI_TYPE]) {
		mynla_get(vf[IFLA_PORT_VSI_TYPE], sizeof portvsi, &portvsi);
		vsi->vsi_mgrid = portvsi.vsi_mgr_id;
		vsi->vsi_typeversion = portvsi.vsi_type_version;
		vsi->vsi_typeid = portvsi.vsi_type_id[0] << 16
				  | portvsi.vsi_type_id[1] << 8
				  | portvsi.vsi_type_id[2] << 8;
	} else
		return -EINVAL;
	vsi->macsz = 0;		/* No returned filter data */
	return 0;
}

/*
 * Parse the IFLA_VF_PORTS block of the netlink message. Expect many
 * IFLA_VF_PORT attribute and search the one we are looking for.
 * Return zero on success and errno else.
 *
 * Code to parse netlink message format 1.
 */
static int trigger_vf_ports(struct vdpnl_vsi *vsi, struct nlattr *tb)
{
	struct nlattr *pos;
	int rest, rc = 0;

	for (rest = mynla_payload(tb), pos = mynla_data(tb);
		mynla_ok(pos, rest) && rc == 0; pos = mynla_next(pos, &rest)) {
		if (mynla_type(pos) == IFLA_VF_PORT)
			rc = trigger_vf_port(vsi, pos);
		else
			rc = -EINVAL;
	}
	return rc;
}

/*
 * Parse the IFLA_VF_INFO block.
 */
static int trigger_vf_info(struct vdpnl_mac *p, struct nlattr *tb)
{
	struct nlattr *vf[IFLA_VF_MAX + 1];
	struct ifla_vf_mac ifla_vf_mac;
	struct ifla_vf_vlan ifla_vf_vlan;
	int rc;

	memset(vf, 0, sizeof(vf));
	memset(&ifla_vf_mac, 0, sizeof(ifla_vf_mac));
	memset(&ifla_vf_vlan, 0, sizeof(ifla_vf_vlan));
	rc = mynla_parse(vf, DIM(vf), mynla_data(tb), mynla_payload(tb));
	if (rc)
		return -EINVAL;
	if (vf[IFLA_VF_MAC]) {
		mynla_get(vf[IFLA_VF_MAC], sizeof ifla_vf_mac, &ifla_vf_mac);
		memcpy(p->mac, ifla_vf_mac.mac, sizeof(p->mac));
	} else
		return -EINVAL;
	if (vf[IFLA_VF_VLAN]) {
		mynla_get(vf[IFLA_VF_VLAN], sizeof ifla_vf_vlan, &ifla_vf_vlan);
		p->vlan = ifla_vf_vlan.vlan & 0xfff;
		p->qos = ifla_vf_vlan.qos & 0xf;
	} else
		return -EINVAL;
	return 0;
}

/*
 * Parse the IFLA_VFINFO_LIST block which contains blocks of VF_INFO blocks.
 */
static int trigger_vfinfo_list(struct vdpnl_vsi *p, struct nlattr *tb)
{
	struct nlattr *pos;
	int i = 0, rest, rc = 0;

	if (p->macsz)		/* This must be netlink format 2 */
		return -EINVAL;
	for (rest = mynla_payload(tb), pos = mynla_data(tb);
		mynla_ok(pos, rest); pos = mynla_next(pos, &rest)) {
		++p->macsz;
	}
	if (!p->macsz)		/* No VLAN/MAC pair */
		return -EINVAL;
	p->maclist = calloc(p->macsz, sizeof(*p->maclist));
	if (!p->maclist) {
		p->macsz = 0;
		return -ENOMEM;
	}
	for (rest = mynla_payload(tb), pos = mynla_data(tb);
			mynla_ok(pos, rest) && rc == 0;
					++i, pos = mynla_next(pos, &rest)) {
		if (mynla_type(pos) == IFLA_VF_INFO)
			rc = trigger_vf_info(&p->maclist[i], pos);
		else
			rc = -EINVAL;
	}
	if (rc) {
		free(p->maclist);
		p->maclist = NULL;
		p->macsz = 0;
	}
	return rc;
}

/*
 * Scan an unsolicited message from lldpad and parse the response for the UUID.
 *
 * Return
 * < 0 on error
 * 0 success
 */
static int vdpnl_trigger_parse(struct vdpnl_vsi *p, unsigned char *buf,
				size_t len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *tb[IFLA_MAX + 1];
	int rc;

	if (len < nlh->nlmsg_len)
		return -ENOMEM;
	memset(tb, 0, sizeof(tb));
	rc = mynla_parse(tb, DIM(tb),
			 (struct nlattr *)IFLA_RTA(NLMSG_DATA(nlh)),
			 IFLA_PAYLOAD(nlh));
	if (rc || !tb[IFLA_VF_PORTS] || !tb[IFLA_IFNAME]
	    || !tb[IFLA_VFINFO_LIST])
		return -EINVAL;
	mynla_get(tb[IFLA_IFNAME], sizeof(p->ifname), p->ifname);
	return trigger_vf_ports(p, tb[IFLA_VF_PORTS])
		| trigger_vfinfo_list(p, tb[IFLA_VFINFO_LIST]);
}


/*
 * Code for construction vdp protocol messages.
 */
enum {
	f_map,
	f_mgrid,
	f_typeid,
	f_typeidver,
	f_uuid,
	f_hints,
	f_2mgrid
};

enum {
	fid_clr = 0,			/* Returned filter check */
	fid_ok = 1,			/* Filter changed ok */
	fid_mod = 2			/* Filter modified unexpectedly */
};

struct macvlan {
	unsigned char mac[ETH_ALEN];	/* MAC address */
	unsigned short vlanid;		/* VLAN Id */
	unsigned long gpid;		/* Group */
	unsigned short newvid;		/* New vlan id returned from switch */
	unsigned char flags;		/* Tested? */
};

#define	CMDTABSZ	32		/* Table size for VSI commands */
static struct vdpdata {
	char key[KEYLEN];	/* Profile name */
	unsigned char modified;	/* Field altered */
	unsigned char pairs;	/* # of MAC/VLAN pairs */
	unsigned char mgrid;	/* Manager ID */
	unsigned char typeidver;	/* Type ID version */
	unsigned int typeid;	/* Type ID */
	unsigned char uuid[PORT_UUID_MAX];	/* Instance ID */
	unsigned char mgrid2[PORT_UUID_MAX];	/* Manager ID VDP22 */
	struct macvlan addr[10];	/* Pairs of MAC/VLAN */
	unsigned char fif;	/* Filter info format */
	unsigned char hints;	/* Migrate to/from hits */
	unsigned char nlmsg_v;	/* Version of netlink message to use */
} vsidata[CMDTABSZ];

struct vdpback {			/* Reply data from lldpad */
	unsigned char uuid[PORT_UUID_MAX];	/* Instance ID */
	unsigned short resp;		/* Response */
	unsigned char pairs;		/* # of returned VLAN */
	struct macvlan addr[10];	/* Pairs of MAC/VLAN */
};

static struct command {		/* Command structure */
	char key[KEYLEN];	/* Name of profile to use */
	unsigned int waittime;	/* Time (in secs) to wait after cmd */
	unsigned int repeats;	/* # of times to repeat this command */
	unsigned int delay;	/* Delay (in us) before a GETLINK msg */
	unsigned char cmd;	/* Type of command */
	unsigned char no_err;	/* # of expected errors */
	int errors[4];		/* Expected errors */
	int rc;			/* Encountered error */
	int sys_rc;		/* System error on send/receive of messages */
	char *text;		/* Text to display */
} cmds[CMDTABSZ], defaults = {	/* Default values in structure */
	.waittime = 1,
	.repeats = 1,
	.delay = 1000
};

static char *progname;
static int verbose;
static char *tokens[256];	/* Used to parse command line params */
static unsigned int cmdidx;	/* Index into cmds[] array */
static int ifindex;		/* Index of ifname */
static char *ifname;		/* Interface to operate on */
static pid_t lldpad;		/* LLDPAD process identifier */
static int my_sock;		/* Netlink socket for lldpad talk */

static void uuid2buf(const unsigned char *p, char *buf)
{
	sprintf(buf, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

#if 0
static void showmac(struct vdpnl_vsi *p)
{
	int i;
	struct vdpnl_mac *macp = p->maclist;

	for (i = 0; i < p->macsz; ++i, ++macp)
		printf("\tvlan:%hd qos:%d\n", macp->vlan, macp->qos);
}
#endif

static int test_new(unsigned short new, unsigned short me)
{
	unsigned short new_vlan = (new & 0xfff);
	unsigned char new_qos = (new >> 12) & 0xf;
	unsigned short vlan = (me & 0xfff);
	unsigned char qos = (me >> 12) & 0xf;

	return (vlan == new_vlan && qos == new_qos);
}

static void expect_fid(struct vdpdata *vdp)
{
	int i;
	struct macvlan *mac = vdp->addr;

	printf(" expected");
	for (i = 0; i < vdp->pairs; ++i, ++mac)
		if( mac->flags == fid_clr)
			printf(" [%hu,%hu]",
				(mac->newvid ?: mac->vlanid) & 0xfff,
				(mac->newvid ?: mac->vlanid) >> 12 & 0xf);
}

static int test_fid(struct vdpnl_mac *new, struct vdpdata *vdp)
{
	int i;
	struct macvlan *mac = vdp->addr;

	for (i = 0; i < vdp->pairs; ++i, ++mac) {
		if (mac->flags == fid_clr) {
			if (test_new(new->vlan, mac->newvid ?: mac->vlanid)) {
				mac->flags = fid_ok;
				return 0;
			}
		}
	}
	return BAD_FILTER;
}

static int compare_fid(struct vdpnl_vsi *back, struct vdpdata *vdp)
{
	int rc = 0, i;

	for (i = 0; i < vdp->pairs; ++i)
		vdp->addr[i].flags = fid_clr;
	/*
	 * Check each returned filter data. Should be in the list of newvid.
	 */
	for (i = 0; rc == 0 && i < back->macsz; ++i) {
		rc |= test_fid(&back->maclist[i], vdp);
		if (verbose >= 3) {
			printf("%s fid:%d vlan:%hu qos:%hu",
				progname, i, back->maclist[i].vlan & 0xfff,
				(back->maclist[i].vlan >> 12) & 0xf);
			if (rc)
				expect_fid(vdp);
			else
				printf(" match ok");
			printf("\n");
		}
	}
	return rc;
}

static int compare_vsi(struct vdpnl_vsi *p, struct vdpdata *vdp)
{
	int rc = 0;

	if (verbose >= 2) {
		char uuidbuf[64];

		uuid2buf(p->vsi_uuid, uuidbuf);
		printf("%s uuid:%s response:%d no_vlanid:%hd\n", progname,
			uuidbuf, p->response, p->macsz);
	}
	rc = compare_fid(p, vdp);
	return rc;
}

/*
 * Wait for a message from LLDPAD
 *
 * Return number of bytes received. 0 means timeout and -1 on error.
 */
static int lldp_waitmsg(int waittime, unsigned char *msgbuf, size_t msgbuf_len)
{
	struct timeval tv1, tv2, tv_res;
	struct sockaddr_nl dest_addr;
	struct iovec iov = {
		.iov_base = msgbuf,
		.iov_len = msgbuf_len
	};
	struct msghdr msg = {
		.msg_name = &dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_controllen = 0,
		.msg_control = 0
	};
	int n, result = 0;
	fd_set readfds;

	struct timeval tv = {
		.tv_sec = waittime
	};

	if (verbose)
		printf("%s Waiting %d seconds for message...\n", progname,
		    waittime);
	FD_ZERO(&readfds);
	FD_SET(my_sock, &readfds);
	gettimeofday(&tv1, NULL);
	n = select(my_sock + 1, &readfds, NULL, NULL, &tv);
	gettimeofday(&tv2, NULL);
	timersub(&tv2, &tv1, &tv_res);
	if (n <= 0) {
		if (n < 0)
			fprintf(stderr, "%s error netlink socket:%s\n",
			    progname, strerror(errno));
		if (n == 0)
			if (verbose)
				printf("%s no netlink response received\n",
				    progname);
		return n;
	}
	memset(msgbuf, 0, msgbuf_len);
	memset(&dest_addr, 0, sizeof(dest_addr));
	result = recvmsg(my_sock, &msg, MSG_DONTWAIT);
	if (result < 0)
		fprintf(stderr, "%s receive error:%s wait:%ld:%06ld\n\n",
			progname, strerror(errno), tv_res.tv_sec,
			tv_res.tv_usec);
	else if (verbose)
		printf("%s received %d bytes from %d wait:%ld:%06ld\n",
			progname, result, dest_addr.nl_pid, tv_res.tv_sec,
			tv_res.tv_usec);
	return result;
}

/*
 * Find out which vdp this unsolicited message was sent for.
 */
static struct vdpdata *finduuid(unsigned char *uuid)
{
	unsigned int i;

	for (i = 0; i < DIM(vsidata); ++i)
		if (!memcmp(vsidata[i].uuid, uuid, sizeof(vsidata[i].uuid)))
			return &vsidata[i];
	return 0;
}

static int trigger_test(struct vdpnl_vsi *p)
{
	char uuid[64];
	int rc = -1;

	uuid2buf(p->vsi_uuid, uuid);
	if (finduuid(p->vsi_uuid)) {
		if (p->response == PORT_REQUEST_DISASSOCIATE)
			rc = 1;
	}
	if (p->maclist)
		free(p->maclist);
	if (verbose >= 2)
		printf("%s switch dis-assoc %s rc:%d\n", progname, uuid, rc);
	return rc;
}

int vdpnl_trigger_parse(struct vdpnl_vsi *, unsigned char *, size_t);

static void lldp_wait(struct command *cp)
{
	int rc = 0;
	unsigned int cnt;
	unsigned char rcvbuf[2 * 1024];
	struct vdpnl_vsi p;

	for (cnt = 0; cnt < cp->repeats && rc >= 0; ++cnt) {
		cp->sys_rc = cp->rc = 0;
		rc = lldp_waitmsg(cp->waittime, rcvbuf, sizeof(rcvbuf));
		if (rc < 0) {
			cp->sys_rc = rc;
			break;
		}
		if (rc > 0) {	/* Check for de-assoc message */
			memset(&p, 0, sizeof(p));
			rc = vdpnl_trigger_parse(&p, rcvbuf, sizeof(rcvbuf));
			if (rc < 0)
				cp->sys_rc = rc;
			else
				cp->rc = trigger_test(&p);
			break;
		}
	}
}

/*
 * Send a GETLINK message to lldpad to query the status of the operation.
 */
static int lldp_getlink(void)
{
	char msgbuf[256];
	struct iovec iov = {
		.iov_base = msgbuf,
		.iov_len = sizeof(msgbuf),
	};
	struct sockaddr_nl dest_addr;
	struct msghdr msg = {
		.msg_name = &dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_controllen = 0,
		.msg_control = 0
	};
	struct nlmsghdr *nlh = (struct nlmsghdr *)msgbuf;
	struct ifinfomsg ifinfo;
	int rc;

	memset(msgbuf, 0, sizeof(msgbuf));
	ifinfo.ifi_index = ifindex;
	ifinfo.ifi_family = AF_UNSPEC;

	/* Fill the netlink message header */
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(ifinfo));
	memcpy(NLMSG_DATA(nlh), &ifinfo, sizeof(ifinfo));
	mynla_put(nlh, IFLA_IFNAME, 1 + strlen(ifname), ifname);
	iov.iov_len =  nlh->nlmsg_len;

	/* Destination address */
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = PF_NETLINK;
	dest_addr.nl_pid = lldpad;

	if ((rc = sendmsg(my_sock, &msg, 0)) == -1)
		perror(progname);
	if (verbose)
		printf("%s query status --> rc:%d\n", progname, rc);
	return rc;
}

/*
 * Send a RTM_GETLINK message and retrieve the status of the pending
 * command.
 *
 * Return
 * <0 send/receive error
 * 0  send/receive ok, but returned netlink message contains netlink error
 * 1  send/receive ok, returned netlink message contains parsed response
 * 2  send/receive ok, but no message returned at all
 */
int vdpnl_getreply_error(unsigned char *, size_t, int *);
int vdpnl_getreply_parse(struct vdpnl_vsi *, unsigned char *, size_t);

static int lldp_recv(struct command *cp, struct vdpnl_vsi *p)
{
	unsigned int cnt;
	int rc, rc2, bytes;
	unsigned char rcvbuf[2 * 1024];

	for (bytes = 0, cnt = 0; cnt < cp->repeats && bytes == 0; ++cnt) {
		usleep(cp->delay * 1000);
		cp->sys_rc = lldp_getlink();
		if (cp->sys_rc < 0)
			return cp->sys_rc;
		cp->rc = cp->sys_rc = 0;
		bytes = lldp_waitmsg(cp->waittime, rcvbuf, sizeof(rcvbuf));
		if (bytes < 0)			/* Error */
			return cp->sys_rc = bytes;
		if (bytes > 0) {			/* Got reply */
			rc2 = vdpnl_getreply_error(rcvbuf, sizeof(rcvbuf), &rc);
			if (rc2 < 0) {		/* Parsing failed */
				if (verbose)
					printf("%s getlink errmsg parse "
						"error:%d\n", progname, rc2);
				return cp->sys_rc = cp->rc = rc2;
			} else if (rc2 == 1) {	/* Error reply */
				if (verbose)
					printf("%s getlink error response:%d\n",
						progname, rc);
				cp->rc = rc;
				return 0;
			}
			/* Normal reply, parsed ok */
			rc2 = vdpnl_getreply_parse(p, rcvbuf, sizeof(rcvbuf));
			if (rc2 < 0) {		/* Parsing failed */
				if (verbose)
					printf("%s getlink parse error rc:%d\n",
						progname, rc2);
				return cp->sys_rc = cp->rc = rc2;
			} else if (rc2 == 1) {	/* Found reply */
				cp->rc = p->response;
				return 1;
			} else if (rc2 == 0) {
				/* Reply without UUID/RESPONSE attribute */
				if (verbose >= 2)
					printf("%s getlink parse UUID/RESPONSE"
						" missing\n", progname);
				cp->rc = -1;
			}
		}
	}
	return 2;
}

static int check_sendack(struct nlmsghdr *nlh, int *ack)
{
	struct nlmsgerr *err = NLMSG_DATA(nlh);

	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -1;
	if (verbose)
		printf("%s setlink response:%d\n", progname, err->error);
	*ack = err->error;
	return 0;
}

/*
 * Send a netlink message to lldpad. Its a SETLINK message to trigger an
 * action. LLDPAD responds with an error netlink message indicating if the
 * profile was accepted.
 * LLDPAD sends negative numbers as error indicators.
 */
static int lldp_send(struct vdpnl_vsi *vsi, int waittime, int *ack)
{
	unsigned char msgbuf[2 * 1024];
	struct iovec iov = {
		.iov_base = msgbuf,
		.iov_len = sizeof(msgbuf),
	};
	struct sockaddr_nl dest_addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = 0,
		.nl_pid = lldpad		/* Target PID */
	};
	struct msghdr msg = {
		.msg_name = &dest_addr,
		.msg_namelen = sizeof(dest_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_controllen = 0,
		.msg_control = 0
	};
	struct nlmsghdr *nlh = (struct nlmsghdr *)msgbuf;
	int rc;

	memset(msgbuf, 0, sizeof msgbuf);
	rc = vdpnl_request_build(vsi, msgbuf, sizeof(msgbuf));
	if (rc < 0) {
		fprintf(stderr, "%s: can not build netlink msg (ver %d): %d\n",
			progname, vsi->nl_version, rc);
		return rc;
	}

	iov.iov_len = nlh->nlmsg_len;		/* Set  msg length */
	rc = sendmsg(my_sock, &msg, 0);
	if (rc < 0){
		perror(progname);
		return rc;
	}
	if (verbose)
		printf("%s send message to %d --> rc:%d\n", progname, lldpad,
			rc);
	rc = lldp_waitmsg(waittime, msgbuf, sizeof(msgbuf));
	if (rc > 0)
		 rc = check_sendack(nlh, ack);
	else if (rc == 0)	/* Time out */
		rc = -1;
	return rc;
}

static unsigned char cvt_request(unsigned char cmd)
{
	switch (cmd) {
	case CMD_ASSOC:
		return PORT_REQUEST_ASSOCIATE;
	case CMD_DEASSOC:
		return PORT_REQUEST_DISASSOCIATE;
	case CMD_PREASSOC:
		return PORT_REQUEST_PREASSOCIATE;
	case CMD_RRPREASSOC:
		return PORT_REQUEST_PREASSOCIATE_RR;
	}
	return PORT_REQUEST_PREASSOCIATE;
}

/*
 * Convert vdp to vsi structure.
 */
static void vdp2vsi(struct vdpnl_vsi *p, unsigned char cmd, struct vdpdata *vdp)
{
	int i;
	static unsigned long nlseq;
	struct vdpnl_mac *mac = p->maclist;

	strncpy(p->ifname, ifname, sizeof(p->ifname) - 1);
	p->ifindex = ifindex;
	p->vf = PORT_SELF_VF;
	p->nl_version = vdp->nlmsg_v;
	p->request = cvt_request(cmd);
	p->req_seq = ++nlseq;
	p->vsi_typeversion = vdp->typeidver;
	p->vsi_typeid = vdp->typeid;
	p->vsi_mgrid = vdp->mgrid;
	p->hints = vdp->hints;
	p->vsi_idfmt = VDP22_ID_UUID;
	memcpy(p->vsi_uuid, vdp->uuid, sizeof(p->vsi_uuid));
	memcpy(p->vsi_mgrid2, vdp->mgrid2, sizeof(p->vsi_mgrid2));
	p->filter_fmt = vdp->fif;
	for (i = 0; i < p->macsz; ++ i, ++mac) {
		mac->vlan = vdp->addr[i].vlanid;
		mac->gpid = vdp->addr[i].gpid;
		memcpy(mac->mac, vdp->addr[i].mac, sizeof(mac->mac));
	}
}

static void clear_vsi(struct vdpnl_vsi *vsi, struct vdpnl_mac *macp, size_t sz)
{
	memset(vsi, 0, sizeof(*vsi));
	memset(macp, 0, sizeof(*macp) * sz);
	vsi->macsz = sz;
	vsi->maclist = macp;
}

/*
 * Convey a message to lldpad.
 *
 * Return
 * 1 for response from lldpad GETLINK command
 * 0 for error response as sendack from lldpad (in cp->rc)
 * -1 for system error (in cp->sys_rc)
 */
static void cmd_lldp(struct command *cp, struct vdpdata *vdp)
{
	int lldpad_cmdack;
	struct vdpnl_mac mac[vdp->pairs];
	struct vdpnl_vsi vsi;

	/* Send command */
	clear_vsi(&vsi, mac, vdp->pairs);
	vdp2vsi(&vsi, cp->cmd, vdp);
	cp->rc = 0;
	cp->sys_rc = lldp_send(&vsi, cp->waittime, &lldpad_cmdack);
	if (cp->sys_rc < 0)
		return;
	cp->rc = lldpad_cmdack;
	if (cp->rc)
		return;
	/* Receive reply */
	clear_vsi(&vsi, mac, vdp->pairs);
	memcpy(vsi.vsi_uuid, vdp->uuid, sizeof(vsi.vsi_uuid));
	if (lldp_recv(cp, &vsi) == 1) {
		if (vsi.macsz)
			cp->rc = compare_vsi(&vsi, vdp);
	}
}

/*
 * Open netlink socket to talk to lldpad daemon.
 */
static int open_socket(int protocol)
{
	int sd;
	int rcv_size = 8 * 1024;
	struct sockaddr_nl snl;

	sd = socket(PF_NETLINK, SOCK_RAW, protocol);
	if (sd < 0) {
		perror("socket");
		return sd;
	}
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int)) < 0) {
		perror("setsockopt");
		close(sd);
		return -EIO;
	}
	memset(&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid = getpid();
	if (bind(sd, (struct sockaddr *)&snl, sizeof snl) < 0) {
		perror("bind");
		close(sd);
		return -EIO;
	}
	return sd;
}

/*
 * Get PID of lldpad from 'ping' command
 */
static void lldpad_pid(void)
{
	lldpad = clif_getpid();
	if (!lldpad) {
		fprintf(stderr, "%s error getting pid of lldpad\n",
			progname);
		exit(5);
	}
	if (verbose >= 2)
		printf("%s my pid %d lldpad pid %d\n", progname, getpid(),
		    lldpad);
}

/*
 * Functions to parse command line parameters
 */
/*
 * Convert a number from ascii to int.
 */
static unsigned long getnumber(char *key, char *word, char stopchar, int *ec)
{
	char *endp;
	unsigned long no;

	if (word == 0 || *word == '\0') {
		fprintf(stderr, "key %s has missing number\n", key);
		*ec = 1;
		return 0;
	}
	no = strtoul(word, &endp, 0);
#ifdef MYDEBUG
	printf("%s:stopchar:%c endp:%c\n", __func__, stopchar, *endp);
#endif
	if (*endp != stopchar) {
		fprintf(stderr, "key %s has invalid parameter %s\n", key, word);
		*ec = 1;
		return 0;
	}
	*ec = 0;
	return no;
}

/*
 * Remove all whitespace from string.
 */
static void kill_white(char *s)
{
	char *cp = s;

	for (; *s != '\0'; ++s) {
		if (isspace(*s))
			continue;
		if (isprint(*s))
			*cp++ = *s;
	}
	*cp = '\0';
}

static void settokens(char *parm)
{
	unsigned int i;

	kill_white(parm);
	for (i = 0; i < DIM(tokens) && (tokens[i] = strtok(parm, ",")) != 0;
	    ++i, parm = 0) {
#ifdef MYDEBUG
		printf("%s:tokens[%d]:%s:\n", __func__, i, tokens[i]);
#endif
	}
}

static struct vdpdata *findkey(char *name)
{
	unsigned int i;

	for (i = 0; i < DIM(vsidata); ++i)
		if (!strncmp(vsidata[i].key, name, strlen(name)))
			return &vsidata[i];
	return 0;
}

static struct vdpdata *nextfree()
{
	unsigned int i;

	for (i = 0; i < DIM(vsidata); ++i)
		if (!vsidata[i].key[0])
			return &vsidata[i];
	return 0;
}

static int check_map(char *value, struct vdpdata *profile)
{
	char *delim2 = 0, *slash, *delim = strchr(value, '-');
	unsigned long vlan, newvlan = 0, gpid = 0;
	int fif, i, ec, x[ETH_ALEN];
	int have_mac = 1, have_gpid = 1;

	if (!delim)
		have_gpid = have_mac = 0;
	else {
		*delim = '\0';
		delim2 = strchr(delim + 1, '-');
		if (!delim2)
			have_gpid = 0;
		else {
			*delim2 = '\0';
			if (delim + 1 == delim2)	/* -- and no mac */
				have_mac = 0;
		}
	}
	memset(x, 0, sizeof(x));
	slash = strchr(value, '/');
	if (slash) {		/* Expect replacement vid incl. changed QoS */
		*slash = '\0';
		newvlan = getnumber("map", slash + 1, '\0', &ec);
		if (ec) {
			fprintf(stderr, "%s invalid new vlanid %s\n", progname,
				value);
			return -1;
		}
		if (newvlan >= 0x10000) {
			fprintf(stderr, "%s new vlanid %#lx too high\n",
				progname, newvlan);
			return -1;
		}
		profile->nlmsg_v = vdpnl_nlf2;
	}
	vlan = getnumber("map", value, '\0', &ec);
	if (ec) {
		fprintf(stderr, "%s invalid vlanid %s\n", progname, value);
		return -1;
	}
	if (vlan >= 0x10000) {
		fprintf(stderr, "%s vlanid %ld too high\n", progname, vlan);
		return -1;
	}
	fif = VDP22_FFMT_VID;
	if (have_mac) {
		ec = sscanf(delim + 1, "%02x:%02x:%02x:%02x:%02x:%02x", &x[0],
				&x[1], &x[2], &x[3], &x[4], &x[5]);
		if (ec != ETH_ALEN) {
			fprintf(stderr, "%s mac %s invalid\n", progname, delim);
			return -1;
		}
		/* Check for last character */
		delim = strrchr(delim + 1, ':') + 2;
		if (*delim && (strchr("0123456789abcdefABCDEF", *delim) == 0
			|| *(delim + 1) != '\0')) {
			fprintf(stderr, "%s last mac part %s invalid\n",
					progname, delim);
			return -1;
		}
		fif = VDP22_FFMT_MACVID;
	}
	/* Check for optional group identifier */
	if (have_gpid && *(delim2 + 1)) {
		gpid = getnumber("group", delim2 + 1, '\0', &ec);
		if (ec) {
			fprintf(stderr, "%s invalid groupid %s\n", progname,
				delim2 + 1);
			return -1;
		}
		fif += 2;
		profile->nlmsg_v = vdpnl_nlf2;
	}
#ifdef MYDEBUG
	for (i = 0; i < ETH_ALEN; ++i)
		printf("x[%d]=%#x ", i, x[i]);
	puts("");

#endif
	if (profile->fif && profile->fif != fif) {
		fprintf(stderr, "%s invalid filter info format %d use %d\n",
		    progname, fif, profile->fif);
		return -1;
	}
	profile->fif = fif;
	for (ec = 0; ec < profile->pairs; ++ec) {
		if (DIM(profile->addr) == i) {
			fprintf(stderr, "%s too many filter addresses\n",
			    progname);
			return -1;
		}
		if (profile->fif == VDP22_FFMT_MACVID
		    || profile->fif == VDP22_FFMT_GROUPMACVID)  {
			for (i = 0; i < ETH_ALEN; ++i)
				if (profile->addr[ec].mac[i] != x[i])
					break;
			if (i == ETH_ALEN) {
				fprintf(stderr, "%s duplicate mac address %s\n",
				    progname, value);
			return -1;
			}
		}
	}
	ec = profile->pairs++;
	profile->addr[ec].vlanid = vlan;
	profile->addr[ec].newvid = newvlan;
	profile->addr[ec].gpid = gpid;
	for (i = 0; i < ETH_ALEN; ++i)
		profile->addr[ec].mac[i] = x[i];
	profile->modified |= 1 << f_map;
	return 0;
}

static int check_uuid(char *value, struct vdpdata *profile)
{
	unsigned int rc;
	unsigned int p[PORT_UUID_MAX];

	rc = sscanf(value, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		&p[0], &p[1], &p[2], &p[3], &p[4], &p[5], &p[6], &p[7],
		&p[8], &p[9], &p[10], &p[11], &p[12], &p[13], &p[14], &p[15]);
#ifdef MYDEBUG
	int i;

	printf("cc=%d\n", rc);
	for (i = 0; i < PORT_UUID_MAX; ++i)
		printf("p[%d]=%#x ", i, p[i]);
	puts("");
#endif
	if (rc != PORT_UUID_MAX) {
		fprintf(stderr, "%s invalid uuid %s\n", progname, value);
		return -1;
	}
	for (rc = 0; rc < sizeof(profile->uuid); ++rc)
		profile->uuid[rc] = p[rc];
	profile->modified |= 1 << f_uuid;
	return 0;
}

static int check_typeid(char *value, struct vdpdata *profile)
{
	unsigned long no;
	int ec;

	no = getnumber("typeid", value, '\0', &ec);
	if (!ec) {
		if ((no & 0xff000000) == 0) {
			profile->typeid = no;
			profile->modified |= 1 << f_typeid;
		} else {
			ec = -1;
			fprintf(stderr, "%s: invalid typeid %ld\n",
			    progname, no);
		}
#ifdef MYDEBUG
		printf("%s:typeid:%d ec:%d\n", __func__, profile->typeid, ec);
#endif
	}
	return ec;
}

static int check_typeidversion(char *value, struct vdpdata *profile)
{
	unsigned long no;
	int ec;

	no = getnumber("typeidver", value, '\0', &ec);
	if (!ec) {
		if (no <= 255) {
			profile->typeidver = no;
			profile->modified |= 1 << f_typeidver;
		} else {
			ec = -1;
			fprintf(stderr, "%s: invalid typeidver %ld\n",
			    progname, no);
		}
#ifdef MYDEBUG
		printf("%s:typeidver:%d ec:%d\n", __func__, profile->typeidver,
		       ec);
#endif
	}
	return ec;
}

static int check_mgrid(char *value, struct vdpdata *profile)
{
	unsigned long no;
	int ec;

	if (profile->nlmsg_v == vdpnl_nlf2) {
		fprintf(stderr, "%s: mgrid and 2mgrid specified\n", progname);
		return -1;
	}
	no = getnumber("mgrid", value, '\0', &ec);
	if (!ec) {
		if (no <= 255 && no > 0) {
			profile->nlmsg_v = vdpnl_nlf1;
			profile->mgrid = no;
			profile->modified |= 1 << f_mgrid;
			memset(profile->mgrid2, 0, sizeof(profile->mgrid2));
		} else {
			ec = -1;
			fprintf(stderr, "%s: invalid mgrid %ld\n", progname,
			    no);
		}
#ifdef MYDEBUG
		printf("%s:mgrid:%d ec:%d\n", __func__, profile->mgrid, ec);
#endif
	}
	return ec;
}

static int check_2mgrid(char *value, struct vdpdata *profile)
{
	if (profile->nlmsg_v == vdpnl_nlf1) {
		fprintf(stderr, "%s: mgrid and 2mgrid specified\n", progname);
		return -1;
	}
	memcpy(profile->mgrid2, value, sizeof(profile->mgrid2) - 1);
	profile->mgrid2[sizeof(profile->mgrid2) - 1] = '\0';
	profile->mgrid = 0;
	profile->modified |= 1 << f_mgrid;
	profile->nlmsg_v = vdpnl_nlf2;
	return 0;
}

static int check_hints(char *value, struct vdpdata *profile)
{
	int rc = 0;

	if(!strcmp(value, "to")) {
		profile->hints = VDP22_MIGTO;
		profile->modified |= 1 << f_hints;
		profile->nlmsg_v = vdpnl_nlf2;
	} else if(!strcmp(value, "from")) {
		profile->hints = VDP22_MIGFROM;
		profile->modified |= 1 << f_hints;
		profile->nlmsg_v = vdpnl_nlf2;
	} else if(!strcmp(value, "none")) {
		profile->hints = 0;
		profile->modified |= 1 << f_hints;
		profile->nlmsg_v = vdpnl_nlf2;
	} else {
		fprintf(stderr, "%s: invalid hints %s\n", progname, value);
		rc = -1;
	}
	return rc;
}


/*
 * Return true if the character is valid for a key
 */
static int check_char(char x)
{
	switch (x) {
	case '-':
	case '_':
		return 1;
	}
	return isalnum(x);
}

static int check_name(char *value, struct vdpdata *profile)
{
	int ec;
	char *cp;

	if (strlen(value) >= DIM(profile->key) - 1) {
		fprintf(stderr, "%s: key %s too long\n", progname, value);
		ec = -1;
		goto out;
	}
	for (cp = value; *cp; ++cp)
		if (!check_char(*cp)) {
			fprintf(stderr, "%s: invalid key %s\n", progname,
			    value);
			ec = -1;
			goto out;
		}
	strcpy(profile->key, value);
	ec = 0;
#ifdef MYDEBUG
	printf("%s:key:%s ec:%d\n", __func__, profile->key, ec);
#endif
out:
	return ec;
}

/*
 * Profile command line keywords. Append new words at end of list.
 */
static char *keytable[] = {
	"map",
	"mgrid",
	"typeidver",
	"typeid",
	"uuid",
	"name",
	"2mgrid",
	"hints"
};

static int findkeyword(char *word)
{
	unsigned int i;

	for (i = 0; i < DIM(keytable); ++i)
		if (!strncmp(keytable[i], word, strlen(keytable[i])))
			return i;
	return -1;
}

static int checkword(char *word, char *value, struct vdpdata *profile)
{
	int rc, idx = findkeyword(word);

	switch (idx) {
	default:
		fprintf(stderr, "%s unknown keyword %s\n", progname, word);
		return -1;
	case 0:
		rc = check_map(value, profile);
		break;
	case 1:
		rc = check_mgrid(value, profile);
		break;
	case 3:
		rc = check_typeid(value, profile);
		break;
	case 2:
		rc = check_typeidversion(value, profile);
		break;
	case 4:
		rc = check_uuid(value, profile);
		break;
	case 5:
		rc = check_name(value, profile);
		break;
	case 6:
		rc = check_2mgrid(value, profile);
		break;
	case 7:
		rc = check_hints(value, profile);
		break;
	}
#ifdef MYDEBUG
	printf("%s word:%s value:%s rc:%d\n", __func__, word, value, rc);
#endif
	return rc;
}

static int setprofile(struct vdpdata *profile)
{
	unsigned int i;
	char *word, *value;

	for (i = 0; i < DIM(tokens) && tokens[i]; ++i) {
		word = tokens[i];
#ifdef MYDEBUG
		printf("%s word:%s tokens[%d]=%s\n", __func__, word, i,
		    tokens[i]);
#endif
		if ((value = strchr(tokens[i], '=')))
			*value++ = '\0';
		else {
			fprintf(stderr, "%s missing argument in %s\n",
			    progname, tokens[i]);
			return -1;
		}
		if (checkword(word, value, profile))
			return -1;
	}
	return 0;
}

static int has_key(struct vdpdata *found)
{
	return found->key[0] != '\0';
}

static void print_pairs(struct vdpdata *found)
{
	int i;

	for (i = 0; i < found->pairs; ++i) {
		printf("\t%hu", found->addr[i].vlanid);
		if (found->addr[i].newvid)
			printf("/%hu", found->addr[i].newvid);
		if (found->fif == VDP22_FFMT_MACVID ||
		    found->fif == VDP22_FFMT_GROUPMACVID) {
			unsigned char *xp = found->addr[i].mac;

			printf(" %02x:%02x:%02x:%02x:%02x:%02x",
				xp[0], xp[1], xp[2], xp[3], xp[4], xp[5]);
		}
		if (found->fif == VDP22_FFMT_GROUPVID ||
		    found->fif == VDP22_FFMT_GROUPMACVID)
			printf(" %ld", found->addr[i].gpid);
		printf("\n");
	}
}

static void print_profile(struct vdpdata *found)
{
	char uuid[64];

	if (found->mgrid)
		sprintf(uuid, "%d", found->mgrid);
	else
		strcpy(uuid, (char *)found->mgrid2);
	printf("key:%s version:%d fif:%d mgrid:%s typeid:%#x typeidver:%d",
	       found->key, found->nlmsg_v, found->fif, uuid, found->typeid,
	       found->typeidver);
	if (found->hints)
		printf(" hints:%s", found->hints == VDP22_MIGTO ? "to" : "from");
	printf("\n");
	uuid2buf(found->uuid, uuid);
	printf("\tuuid:%s\n", uuid);
	if (found->pairs)
		print_pairs(found);
}

static int change_profile(struct vdpdata *change, struct vdpdata *alter)
{
#ifdef MYDEBUG
	printf("%s alter->modified:%#x\n", __func__, alter->modified);
#endif
	if ((alter->modified & (1 << f_map))) {
		change->fif = alter->fif;
		change->pairs = alter->pairs;
		memcpy(change->addr, alter->addr, sizeof alter->addr);
	}
	if ((alter->modified & (1 << f_mgrid))) {
		change->mgrid = alter->mgrid;
		memcpy(change->mgrid2, alter->mgrid2, sizeof(change->mgrid2));
	}
	if ((alter->modified & (1 << f_typeid)))
		change->typeid = alter->typeid;
	if ((alter->modified & (1 << f_typeidver)))
		change->typeidver = alter->typeidver;
	if ((alter->modified & (1 << f_uuid)))
		memcpy(change->uuid, alter->uuid, sizeof change->uuid);
	if ((alter->modified & (1 << f_hints)))
		change->hints = alter->hints;
	change->nlmsg_v = alter->nlmsg_v;
	return 0;
}

static void show_profiles(char *thisone)
{
	unsigned int i;

	if (thisone) {
		struct vdpdata *showme = findkey(thisone);

		if (showme)
			print_profile(showme);
	} else
		for (i = 0; i < DIM(vsidata); ++i)
			if (has_key(&vsidata[i]))
				print_profile(&vsidata[i]);
}

/*
 * Parse the profile string of the form
 * key=###,mgrid=###|2mgrid=xxx,typeid=###,typeidver=###,uuid=xxx,map=xxx{1,10}
 */
static int parse_profile(char *profile, struct vdpdata *target)
{
	struct vdpdata nextone;
	char *copy = strdup(profile);

#ifdef MYDEBUG
	printf("%s profile:%s\n", __func__, profile);
#endif
	memset(&nextone, 0, sizeof nextone);
	settokens(profile);
	if (setprofile(&nextone)) {
		fprintf(stderr, "%s: ignore invalid profile data (%s)\n",
		    progname, copy);
		free(copy);
		return -1;
	}
	if (!has_key(&nextone)) {
		fprintf(stderr, "%s ignore keyless profile data (%s)\n",
		    progname, copy);
		free(copy);
		return -1;
	}
	free(copy);
#ifdef MYDEBUG
	print_profile(&nextone);
#endif
	*target = nextone;
	return 0;
}

static void find_field(unsigned char mode, char *buf)
{
	int comma = 0;

	*buf = '\0';
	if ((mode & (1 << f_map)) == 0) {
		strcat(buf, "map");
		comma = 1;
	}
	if ((mode & (1 << f_mgrid)) == 0) {
		if (comma)
			strcat(buf, ",");
		strcat(buf, "mgrid");
		comma = 1;
	}
	if ((mode & (1 << f_typeid)) == 0) {
		if (comma)
			strcat(buf, ",");
		strcat(buf, "typeid");
		comma = 1;
	}
	if ((mode & (1 << f_typeidver)) == 0) {
		if (comma)
			strcat(buf, ",");
		strcat(buf, "typeidver");
		comma = 1;
	}
	if ((mode & (1 << f_uuid)) == 0) {
		if (comma)
			strcat(buf, ",");
		strcat(buf, "uuid");
	}
	if ((mode & (1 << f_hints)) == 0) {
		if (comma)
			strcat(buf, ",");
		strcat(buf, "hints");
	}
}

static int isvalid_profile(struct vdpdata *vdp)
{
	char buf[64];
	unsigned char mode = 1 << f_map | 1 << f_mgrid |
				1 << f_typeid | 1 << f_typeidver | 1 << f_uuid;
	unsigned char optmode = 1 << f_hints;

	if ((vdp->modified & ~optmode) != mode) {
		find_field(vdp->modified, buf);
		fprintf(stderr, "%s key %s misses profile fields %s\n",
		    progname, vdp->key, buf);
		memset(vdp->key, 0, sizeof vdp->key);
		return -1;
	}
	if (vdp->nlmsg_v != vdpnl_nlf2 && vdp->nlmsg_v != vdpnl_nlf1) {
		fprintf(stderr, "%s key %s has wrong netlink msg format\n",
		    progname, vdp->key);
		memset(vdp->key, 0, sizeof vdp->key);
		return -1;
	}
	return 0;
}

static int make_profiles(char *profile, char *newkey)
{
	struct vdpdata *vdp, nextone;

	if (parse_profile(profile, &nextone))
		return -1;
	if (!newkey) {
		if (findkey(nextone.key)) {
			fprintf(stderr, "%s profile key %s already exits\n",
			    progname, nextone.key);
			return -1;
		}
		if (!(vdp = nextfree())) {
			fprintf(stderr, "%s too many profiles\n", progname);
			return -1;
		}
		*vdp = nextone;
	} else {
		struct vdpdata *found;

		if (!(found = findkey(nextone.key))) {
			fprintf(stderr, "%s profile key %s does not exit\n",
			    progname, nextone.key);
			return -1;
		}
		if (!strcmp(newkey, found->key) || findkey(newkey)) {
			fprintf(stderr, "%s target key %s already exits\n",
				progname, newkey);
			return -1;
		}
		if (!(vdp = nextfree())) {
			fprintf(stderr, "%s too many profiles\n", progname);
			return -1;
		}
		*vdp = *found;
		strncpy(vdp->key, newkey, sizeof vdp->key);
		if (!nextone.nlmsg_v)		/* Test for netlink format */
			nextone.nlmsg_v = vdp->nlmsg_v;
		change_profile(vdp, &nextone);
	}
	return isvalid_profile(vdp);
}

static int del_profiles(char *name)
{
	struct vdpdata *vdp;

	if (!(vdp = findkey(name))) {
		fprintf(stderr, "%s profile key %s not found\n", progname,
		    name);
		return -1;
	}
	memset(vdp->key, 0, sizeof vdp->key);
	return 0;
}

static int copy_profiles(char *profile)
{
	char *newprofile, *newkey;

	kill_white(profile);
	if (strncmp(profile, COPY_OP, strlen(COPY_OP))) {
		fprintf(stderr, "%s missing key new=name\n", progname);
		return -1;
	}
	newkey = profile + strlen(COPY_OP);
	newprofile = strchr(newkey, ',');
	if (!newprofile) {
		fprintf(stderr, "%s invalid copy command\n", progname);
		return -1;
	}
	*newprofile = '\0';
	return make_profiles(newprofile + 1, newkey);
}

/*
 * Detect the profile operation
 */
static int forwardline(char *buf)
{
	if (strncmp(buf, COPY_OP, strlen(COPY_OP)) == 0)
		return copy_profiles(buf);
	return make_profiles(buf, 0);

}

/*
 * Read a full line from the file. Remove comments and ignore blank lines.
 * Also concatenate lines terminated with <backslash><newline>.
 */
#define	COMMENT	"#*;"		/* Comments in [#*;] and <newline> */
static char *fullline(FILE * fp, char *buffer, size_t buflen)
{
	int more = 0, off = 0;
	char *cp;
	static int lineno = 0;

	do {
		if ((cp = fgets(buffer + off, buflen - off, fp)) == NULL) {
			if (more == 2) {
				fprintf(stderr, "%s line %d unexpected EOF\n",
				    progname, lineno);
				exit(1);
			}
			return NULL;	/* No more lines */
		}
		++lineno;
		if ((cp = strchr(buffer, '\n')) == NULL) {
			fprintf(stderr, "%s line %d too long", progname,
			    lineno);
			exit(1);
		} else
			*cp = '\0';
		if ((cp = strpbrk(buffer, COMMENT)) != NULL)
			*cp = '\0';	/* Drop comment */
		for (cp = buffer; *cp && isspace(*cp); ++cp)
			;		/* Skip leading space */
		if (*cp == '\0')
			more = 1;	/* Empty line */
		else if (*(cp + strlen(cp) - 1) == '\\') {
			more = 2;	/* Line concatenation */
			*(cp + strlen(cp) - 1) = '\0';
			off = strlen(buffer);
		} else
			more = 0;
	} while (more);
	memmove(buffer, cp, strlen(cp) + 1);
	return buffer;
}

static int read_profiles(char *cfgfile)
{
	FILE *fp;
	char buffer[1024];
	int rc = 0;

	if (strcmp(cfgfile, "-")) {
		if ((fp = fopen(cfgfile, "r")) == NULL) {
			perror(cfgfile);
			exit(1);
		}
	} else {
		fp = stdin;
		cfgfile = "<stdin>";
	}
	while (fullline(fp, buffer, sizeof buffer))
		rc |= forwardline(buffer);
	if (fp != stdin)
		fclose(fp);
	return rc;
}

static char *cmd_name(char cmd)
{
	switch (cmd) {
	case CMD_ASSOC:
		return "assoc";
	case CMD_DEASSOC:
		return "dis-assoc";
	case CMD_PREASSOC:
		return "preassoc";
	case CMD_RRPREASSOC:
		return "rr-preassoc";
	case CMD_SLEEP:
		return "sleep";
	case CMD_ECHO:
		return "echo";
	case CMD_EXTERN:
		return "extern";
	case CMD_GETMSG:
		return "getmsg";
	case CMD_SETDF:
		return "setdf";
	}
	return "unknown";
}

static void show_command(struct command *cmdp, int withrc)
{
	int j;

	printf("%s key:%s waittime:%d repeats:%d delay:%d expected-rc:",
	    cmd_name(cmdp->cmd), cmdp->key, cmdp->waittime, cmdp->repeats,
	    cmdp->delay);
	for (j = 0; j < cmdp->no_err; ++j)
		printf("%d ", cmdp->errors[j]);
	if (withrc)
		printf("rc:%d", cmdp->rc);
	printf("\n");
}

static void show_commands(int withrc)
{
	unsigned int i;

	for (i = 0; i < DIM(cmds) && i < cmdidx; ++i)
		show_command(&cmds[i], withrc);
}

static int filldefaults(char *cmd, char *value)
{
	int no, ec;

	no = getnumber(cmd, value, '\0', &ec);
	if (ec)
		return -1;
	if (*cmd == 'd')
		defaults.delay = no;
	if (*cmd == 'w')
		defaults.waittime = no;
	if (*cmd == 'r')
		defaults.repeats = no;
	return 0;
}

static int setdefaults(char *line)
{
	unsigned int i = 0;
	int rc = 0;

	settokens(line);
	for (; i < DIM(tokens) && tokens[i]; ++i) {
		char *equal = strchr(tokens[i], '=');

		if (!equal) {
			fprintf(stderr, "%s: invalid syntax (%s) for"
			    " command %s\n", progname, tokens[i],
			    cmd_name(CMD_SETDF));
			return -1;
		}
		rc |= filldefaults(tokens[i], equal + 1);
	}
	return rc;
}

static int fillvalue(char *cmd, char *value)
{
	int no, ec;

	no = getnumber(cmd, value, '\0', &ec);
	if (ec)
		return -1;
	if (*cmd == 'd')
		cmds[cmdidx].delay = no;
	if (*cmd == 'w')
		cmds[cmdidx].waittime = no;
	else if (*cmd == 'r')
		cmds[cmdidx].repeats = no;
	else if (*cmd == 'e') {
		if (cmds[cmdidx].no_err >= DIM(cmds[cmdidx].errors)) {
			fprintf(stderr, "%s too many errors expected\n",
			    progname);
			return -1;
		}
		cmds[cmdidx].errors[cmds[cmdidx].no_err++] = no;
	}
	return 0;
}

static int needkey(char x)
{
	return x == CMD_ASSOC || x == CMD_DEASSOC || x == CMD_PREASSOC
	    || x == CMD_RRPREASSOC;
}

static int parse_cmd(char type, char *line)
{
	unsigned int i = 0;
	int rc = 0;

#ifdef MYDEBUG
	printf("%s cmd:%c line:%s cmdidx:%d\n", __func__, type, line, cmdidx);
#endif
	if (cmdidx >= DIM(cmds)) {
		fprintf(stderr, "%s: too many commands\n", progname);
		exit(2);
	}
	cmds[cmdidx].cmd = type;
	if (type == CMD_ECHO) {
		cmds[cmdidx].text = line;
		goto done;
	} else if (type == CMD_EXTERN) {
		cmds[cmdidx].text = line;
		goto done;
	}
	settokens(line);
	if (needkey(type) && !findkey(tokens[i])) {
		fprintf(stderr, "%s: unknown profile %s, command ignored\n",
		    progname, tokens[i]);
		return -1;
	}
	if (needkey(type)) {
		strncpy(cmds[cmdidx].key, tokens[i], strlen(tokens[i]));
		i++;
	} else
		strcpy(cmds[cmdidx].key, "---");

	for (; i < DIM(tokens) && tokens[i]; ++i) {
		char *equal = strchr(tokens[i], '=');

		if (!equal) {
			fprintf(stderr, "%s: invalid syntax (%s) for"
			    " command %s\n", progname, tokens[i],
			    cmd_name(type));
			return -1;
		}
		rc |= fillvalue(tokens[i], equal + 1);
	}
done:
	if (!cmds[cmdidx].no_err) {	/* Default error is 0 */
		cmds[cmdidx].no_err = 1;
		/* Default behavior for GETMSG, time out or 1 message */
		if (cmds[cmdidx].cmd == CMD_GETMSG) {
			cmds[cmdidx].no_err = 2;
			cmds[cmdidx].errors[1] = 1;	/* 1 Message */
		}
	}
	if (!cmds[cmdidx].repeats)	/* Default repeats is 1 */
		cmds[cmdidx].repeats = defaults.repeats;
	if (!cmds[cmdidx].waittime)	/* Default waittime is 1 sec */
		cmds[cmdidx].waittime = defaults.waittime;
	if (!cmds[cmdidx].delay)	/* Default delay is 1 sec */
		cmds[cmdidx].delay = defaults.delay;
	if (rc == 0)
		++cmdidx;
	return rc;
}

static int cmd_checkrc(struct command *cmdp)
{
	int i;

	if (cmdp->sys_rc) {
		printf("FAILURE sys_rc:%d ", cmdp->sys_rc);
		show_command(cmdp, 1);
		return -1;
	}
	for (i = 0; i < cmdp->no_err; ++i)
		if (cmdp->rc == cmdp->errors[i]) {
			if (verbose)
				printf("SUCCESS command %s\n",
				    cmd_name(cmdp->cmd));
			return 0;
		}
	if (verbose) {
		printf("FAILURE ");
		show_command(cmdp, 1);
	}
	return -1;
}

static void cmd_extern(struct command *cmdp)
{
	unsigned int i;
	int rc = 0;

	for (i = 0; i < cmdp->repeats; ++i)
		rc |= system(cmdp->text);
	cmdp->rc = rc;
}

static void cmd_echo(struct command *cmdp)
{
	unsigned int i;

	for (i = 0; i < cmdp->repeats; ++i)
		puts(cmdp->text);
	cmdp->rc = 0;
}

static void cmd_sleep(struct command *cmdp)
{
	unsigned int i;

	if (cmdp->waittime)
		for (i = 0; i < cmdp->repeats; ++i)
			cmdp->rc |= sleep(cmdp->waittime);
}

/*
 * Code to use the command line interface via clif_xxx functions.
 */
static int tool_use;
static struct clif *tool_conn;

static void tool_open()
{
	tool_conn = clif_open();
	if (!tool_conn) {
		fprintf(stderr, "%s can not open connection to LLDPAD\n",
			progname);
		exit(5);
	}
	if (clif_attach(tool_conn, "80c4")) {
		fprintf(stderr, "%s can not attach to LLDPAD\n",
			progname);
		clif_close(tool_conn);
		tool_conn = NULL;
		exit(5);
	}
}

static void tool_close(void)
{
	if (tool_conn) {
		clif_detach(tool_conn);
		clif_close(tool_conn);
		tool_conn = NULL;
	}
}

/*
 * Convert VSI command mode to string.
 */
static unsigned int request2tlvid(unsigned char cmd)
{
	switch (cmd) {
	case CMD_ASSOC:
		return VDP22_ASSOC;
	case CMD_DEASSOC:
		return VDP22_DEASSOC;
	case CMD_PREASSOC:
		return VDP22_PREASSOC;
	case CMD_RRPREASSOC:
		return VDP22_PREASSOC_WITH_RR;
	}
	return 0;
}

static const char *request2str(unsigned char cmd)
{
	switch (cmd) {
	case CMD_ASSOC:
		return "assoc";
	case CMD_DEASSOC:
		return "deassoc";
	case CMD_PREASSOC:
		return "preassoc";
	case CMD_RRPREASSOC:
		return "preassoc-rr";
	}
	return "unknown";
}

/*
 * Convert hint bits to string.
 */
static const char *hints2str(unsigned char hint)
{
	switch (hint) {
	case VDP22_MIGTO:
		return "to";
	case VDP22_MIGFROM:
		return "from";
	default:
		return "none";
	}
}

/*
 * Create a command string understood by vdp22 module to forward it to
 * the vdp22 module.
 */
static size_t vdp2str(char *cmd, size_t cmd_len, char oper, struct vdpdata *vdp)
{
	int i;
	size_t len;
	char uuidbuf[64], mgrid[64];

	uuid2buf(vdp->uuid, uuidbuf);
	if (vdp->nlmsg_v == vdpnl_nlf1)
		sprintf(mgrid, "%d", vdp->mgrid);
	else
		strcpy(mgrid, (char *)vdp->mgrid2);
	snprintf(cmd, cmd_len, "%s,%s,%d,%d,%s,%s",
			request2str(oper), mgrid, vdp->typeid,
			vdp->typeidver, uuidbuf, hints2str(vdp->hints));

	/* Add Filter information data */
	for (i = 0; i < vdp->pairs; ++i) {
		len = strlen(cmd);
		snprintf(cmd + len, cmd_len - len, ",%d",
			 vdp->addr[i].vlanid);
		if (vdp->fif == VDP22_FFMT_MACVID ||
		    vdp->fif == VDP22_FFMT_GROUPMACVID) {
			len = strlen(cmd);
			snprintf(cmd + len, cmd_len - len,
				 "-%02x:%02x:%02x:%02x:%02x:%02x",
				 vdp->addr[i].mac[0], vdp->addr[i].mac[1],
				 vdp->addr[i].mac[2], vdp->addr[i].mac[3],
				 vdp->addr[i].mac[4], vdp->addr[i].mac[5]);
		}
		if (vdp->fif == VDP22_FFMT_GROUPVID ||
		    vdp->fif == VDP22_FFMT_GROUPMACVID) {
			len = strlen(cmd);
			snprintf(cmd + len, cmd_len - len, "-%ld",
					vdp->addr[i].gpid);
		}
	}
	return strlen(cmd);
}

/*
 * Convert ascii string to vdp. Return command.
 */
static char *str2vdp(char *ok, struct vdpdata *p, int *response)
{
	int i, ec;
	char *token, *cmd = NULL;

	for (i = 0, token = strtok(ok, ","); token;
					++i, token = strtok(NULL, ",")) {
		if (i == 0)
			cmd = token;
		if (i == 1) {
			char *myend;
			unsigned long x = strtol(token, &myend, 10);

			if (*myend || x > 255)
				strcpy((char *)p->mgrid2, token);
			else
				p->mgrid = x;
		}
		if (i == 2) {
			p->typeid = getnumber("typeid", token, '\0', &ec);
			if (ec)
				return NULL;
		}
		if (i == 3) {
			p->typeidver = getnumber("typeidver", token, '\0', &ec);
			if (ec)
				return NULL;
		}
		if (i == 4 && check_uuid(token, p))
			return NULL;
		/* Hints field contains response */
		if (i == 5) {
			char *myend;
			unsigned long x = strtol(token, &myend, 10);

			if (*myend)
				return NULL;
			*response = x;
		}
		if (i >= 6 && check_map(token, p))
			return NULL;
	}
	p->modified = 0;
	return cmd;
}

/*
 * Test data of association.
 */
static int check_vsi(struct vdpdata *p, struct vdpdata *back)
{
	int i;

	if (p->mgrid && p->mgrid != back->mgrid) {
		if (verbose >= 2)
			printf("invalid mgrid identifer %d (expected %d)\n",
					 back->mgrid, p->mgrid);
		return -EINVAL;
	}
	if (p->pairs != back->pairs) {
		if (verbose >= 2)
			printf("invalid fid pairs %d (expected %d)\n",
					 back->pairs, p->pairs);
		return -ENFILE;
	}
	for (i = 0; i < p->pairs; ++i) {
		if (p->addr[i].newvid) {
			if (p->addr[i].newvid != back->addr[i].vlanid) {
				if (verbose >= 2) {
					printf("invalid vlanid[%d]:%#hx "
					       "(expected %#hx)\n",
					       i, back->addr[i].vlanid,
					       p->addr[i].newvid);
					return -EMFILE;
				}
			}
		} else if (p->addr[i].vlanid) {
			if (p->addr[i].vlanid != back->addr[i].vlanid) {
				if (verbose >= 2) {
					printf("unexpected vlanid[%d]:%#hx "
						"(expected %#hx)\n",
						i, back->addr[i].vlanid,
						p->addr[i].vlanid);
					return -ENOTTY;
				}
			}
		} else {
			printf("invalid vlanid input[%d]:%#hx "
					"(expected %#hx)\n",
					i, back->addr[i].vlanid,
					p->addr[i].newvid);
			return -ETXTBSY;
		}
	}
	return 0;
}

static void tool_lldp(struct command *cmdp, struct vdpdata *vdp)
{
	char cmd[MAX_CLIF_MSGBUF], ok[MAX_CLIF_MSGBUF];
	size_t ok_len = sizeof(ok);
	struct vdpdata back;

	memset(&back, 0, sizeof(back));
	cmdp->sys_rc = cmdp->rc = 0;
	vdp2str(cmd, sizeof(cmd), cmdp->cmd, vdp);
	cmdp->rc = clif_vsiwait(tool_conn, ifname, request2tlvid(cmdp->cmd),
				cmd, ok, &ok_len, cmdp->waittime);
	if (!cmdp->rc) {
		char *cmd = str2vdp(ok, &back, &cmdp->rc);
		if (!cmd)
			cmdp->rc = -EINVAL;
		if (!strcmp(cmd, request2str(cmdp->cmd)) && !cmdp->rc)
			cmdp->rc = check_vsi(vdp, &back);
	}
}

/*
 * Return 0 with command executed as expected.
 * Maybe with expected error.
 */
static void cmd_profile(struct command *cmdp)
{
	struct vdpdata *vdp = findkey(cmdp->key);

	if (!vdp) {
		cmdp->rc = ENFILE;
		return;
	}
	if (vdp->nlmsg_v == vdpnl_nlf2 || tool_use)
		tool_lldp(cmdp, vdp);
	else
		cmd_lldp(cmdp, vdp);
}

/*
 * Wait for unsolicited messsage from lldpad vdp22 module.
 */
static void tool_wait(struct command *cmdp)
{
	char ok[MAX_CLIF_MSGBUF];
	size_t ok_len = sizeof(ok);

	cmdp->sys_rc = cmdp->rc = 0;
	cmdp->rc = clif_vsievt(tool_conn, ok, &ok_len, cmdp->waittime);
	if (cmdp->rc == -EAGAIN)	/* No message received */
		cmdp->rc = 0;
	else if (cmdp->rc == 0 && !strncmp(ok, "deassoc", strlen("deassoc")))
		/* Data received and dessaoc command */
		cmdp->rc = 1;
}

static int runcmds()
{
	unsigned int i;
	int rc = 0;

	for (i = 0; i < cmdidx && i < DIM(cmds); ++i) {
		if (verbose)
			printf("start command %s waittime:%d\n",
			    cmd_name(cmds[i].cmd), cmds[i].waittime);
		switch (cmds[i].cmd) {
		case CMD_ASSOC:
		case CMD_DEASSOC:
		case CMD_PREASSOC:
		case CMD_RRPREASSOC:
			cmd_profile(&cmds[i]);
			break;
		case CMD_SLEEP:
			cmd_sleep(&cmds[i]);
			break;
		case CMD_EXTERN:
			cmd_extern(&cmds[i]);
			break;
		case CMD_ECHO:
			cmd_echo(&cmds[i]);
			break;
		case CMD_GETMSG:
			if (tool_use)
				tool_wait(&cmds[i]);
			else
				lldp_wait(&cmds[i]);
			break;
		}
		rc = cmd_checkrc(&cmds[i]);
		if (rc)
			break;
	}
	return rc;
}

/*
 * Check for VSI draft 0.2 and draft 2.2 input format on one command line.
 */
static void inputformats(void)
{
	int f1 = 0, f2 = 0;
	unsigned int i;

	for (i = 0; i < DIM(cmds) && i < cmdidx; ++i) {
		if (vsidata[i].nlmsg_v == vdpnl_nlf1)
			++f1;
		if (vsidata[i].nlmsg_v == vdpnl_nlf2)
			++f2;
	}
	if (f1 && f2) {
		fprintf(stderr, "%s mixed input format of VSI draft 0.2"
				" and draft 2.2 not supported\n", progname);
		exit(1);
	}
	if (!f1)		/* Draft 2,2 with clif only */
		tool_use = 1;
}

#include <net/if.h>

int main(int argc, char **argv)
{
	extern int optind, opterr;
	extern char *optarg;
	int ch, rc, needif = 0;
	char *slash, mybuf[32];

	progname = (slash = strrchr(argv[0], '/')) ? slash + 1 : argv[0];
	while ((ch = getopt(argc, argv, ":A:C:D:F:S::a:d:e:E:g:p:r:s::i:vn"))
	    != EOF)
		switch (ch) {
		case '?':
			fprintf(stderr, "%s: unknown option -%c\n", progname,
			    optopt);
			exit(1);
		case ':':
			fprintf(stderr, "%s missing option argument for -%c\n",
			    progname, optopt);
			exit(1);
		case 'n':
			tool_use = 1;
			break;
		case 'F':
			read_profiles(optarg);
			break;
		case 'D':
			del_profiles(optarg);
			break;
		case 'C':
			copy_profiles(optarg);
			break;
		case 'S':
			show_profiles(optarg);
			break;
		case 'A':
			make_profiles(optarg, 0);
			break;
		case 'v':
			++verbose;
			break;
		case 'i':
			ifname = optarg;
			ifindex = if_nametoindex(ifname);
			break;
		case CMD_SETDF:
			if (setdefaults(optarg))
				return 1;
			break;
		case CMD_SLEEP:
			if (!optarg) {
				optarg = mybuf;
				strncpy(mybuf, "w=1", sizeof mybuf);
			}
			parse_cmd(ch, optarg);
			break;
		case CMD_RRPREASSOC:
		case CMD_PREASSOC:
		case CMD_DEASSOC:
		case CMD_ASSOC:
		case CMD_GETMSG:
			needif = 1;	/* Fall through intended */
		case CMD_ECHO:
		case CMD_EXTERN:
			parse_cmd(ch, optarg);
			break;
		}
#ifdef MYDEBUG
	for (; optind < argc; ++optind)
		printf("%d %s\n", optind, argv[optind]);
#endif
	inputformats();
	if (!needif)
		exit(0);
	if (!ifname) {
		fprintf(stderr, "%s interface missing or nonexistant\n",
		    progname);
		exit(2);
	}
	if (tool_use)
		tool_open();
	else {
		lldpad_pid();
		if ((my_sock = open_socket(NETLINK_ROUTE)) < 0)
			exit(4);
	}
	if (verbose >= 2) {
		printf("\nTests to run:\n");
		show_commands(0);
	}
	if (verbose >= 2)
		printf("\nExecution:\n");
	rc = runcmds();
	if (tool_use)
		tool_close();
	else
		close(my_sock);
	if (verbose >= 2) {
		printf("\nSummary:\n");
		show_commands(1);
	}
	return rc;
}
