/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
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
 * Contains netlink message parsing for VDP protocol from libvirtd or other
 * buddies.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>

#include <net/if.h>
#include <netlink/attr.h>
#include <netlink/msg.h>

#include "messages.h"
#include "qbg_vdp.h"
#include "qbg_vdp22.h"
#include "qbg_vdpnl.h"
#include "qbg_utils.h"
#include "lldp_rtnl.h"

static struct nla_policy ifla_vf_policy[IFLA_VF_MAX + 1] = {
	[IFLA_VF_MAC] = {
		.minlen = sizeof(struct ifla_vf_mac),
		.maxlen = sizeof(struct ifla_vf_mac)
	},
	[IFLA_VF_VLAN] = {
		.minlen = sizeof(struct ifla_vf_vlan),
		.maxlen = sizeof(struct ifla_vf_vlan)
	}
};

static struct nla_policy ifla_port_policy[IFLA_PORT_MAX + 1] = {
	[IFLA_PORT_VF]            = { .type = NLA_U32 },
	[IFLA_PORT_PROFILE]       = { .type = NLA_STRING },
	[IFLA_PORT_VSI_TYPE]      = { .minlen = sizeof(struct ifla_port_vsi) },
	[IFLA_PORT_INSTANCE_UUID] = { .minlen = PORT_UUID_MAX,
				      .maxlen = PORT_UUID_MAX, },
	[IFLA_PORT_HOST_UUID]     = { .minlen = PORT_UUID_MAX,
				      .maxlen = PORT_UUID_MAX, },
	[IFLA_PORT_REQUEST]       = { .type = NLA_U8  },
	[IFLA_PORT_RESPONSE]      = { .type = NLA_U16 },
};

static void vdpnl_show(struct vdpnl_vsi *vsi)
{
	char instance[VDP_UUID_STRLEN + 2];
	struct vdpnl_mac *mac;
	int i;

	LLDPAD_DBG("%s:IFLA_IFNAME:%s index:%d\n", __func__, vsi->ifname,
		   vsi->ifindex);
	for (i = 0, mac = vsi->maclist; i < vsi->macsz; ++i, ++mac) {
		LLDPAD_DBG("%s:IFLA_VF_MAC:%2x:%2x:%2x:%2x:%2x:%2x\n",
			   __func__, mac->mac[0], mac->mac[1], mac->mac[2],
			   mac->mac[3], mac->mac[4], mac->mac[5]);
		LLDPAD_DBG("%s:IFLA_VF_VLAN:%d QOS:%d\n", __func__, mac->vlan,
			   mac->qos);
	}
	LLDPAD_DBG("%s:IFLA_PORT_VSI_TYPE:mgr_id:%d type_id:%ld "
		   "typeid_version:%d\n",
		   __func__, vsi->vsi_mgrid, vsi->vsi_typeid,
		   vsi->vsi_typeversion);
	vdp_uuid2str(vsi->vsi_uuid, instance, sizeof(instance));
	LLDPAD_DBG("%s:IFLA_PORT_INSTANCE_UUID:%s\n", __func__, instance);
	LLDPAD_DBG("%s:IFLA_PORT_REQUEST:%d\n", __func__, vsi->request);
	LLDPAD_DBG("%s:IFLA_PORT_RESPONSE:%d\n", __func__, vsi->response);
}

/*
 * Parse the IFLA_IFLA_VF_PORTIFLA_VF_PORTS block of the netlink message.
 * Return zero on success and errno else.
 */
static int vdpnl_vfports(struct nlattr *vfports, struct vdpnl_vsi *vsi)
{
	char instance[VDP_UUID_STRLEN + 2];
	struct nlattr *tb_vf_ports, *tb3[IFLA_PORT_MAX + 1];
	int rem;

	if (!vfports) {
		LLDPAD_DBG("%s:FOUND NO IFLA_VF_PORTS\n", __func__);
		return -EINVAL;
	}

	nla_for_each_nested(tb_vf_ports, vfports, rem) {
		if (nla_type(tb_vf_ports) != IFLA_VF_PORT) {
			LLDPAD_DBG("%s:not a IFLA_VF_PORT skipping\n",
				   __func__);
			continue;
		}
		if (nla_parse_nested(tb3, IFLA_PORT_MAX, tb_vf_ports,
			ifla_port_policy)) {
			LLDPAD_ERR("%s:IFLA_PORT_MAX parsing failed\n",
				   __func__);
			return -EINVAL;
		}
		if (tb3[IFLA_PORT_VF])
			LLDPAD_DBG("%s:IFLA_PORT_VF:%d\n", __func__,
			    *(uint32_t *) RTA_DATA(tb3[IFLA_PORT_VF]));
		if (tb3[IFLA_PORT_PROFILE])
			LLDPAD_DBG("%s:IFLA_PORT_PROFILE:%s\n", __func__,
				   (char *)RTA_DATA(tb3[IFLA_PORT_PROFILE]));
		if (tb3[IFLA_PORT_HOST_UUID]) {
			unsigned char *uuid;

			uuid = (unsigned char *)
				RTA_DATA(tb3[IFLA_PORT_HOST_UUID]);
			vdp_uuid2str(uuid, instance, sizeof(instance));
			LLDPAD_DBG("%s:IFLA_PORT_HOST_UUID:%s\n", __func__,
				   instance);
		}
		if (tb3[IFLA_PORT_VSI_TYPE]) {
			struct ifla_port_vsi *pvsi;
			int tid = 0;

			pvsi = (struct ifla_port_vsi *)
			    RTA_DATA(tb3[IFLA_PORT_VSI_TYPE]);
			tid = pvsi->vsi_type_id[2] << 16 |
			    pvsi->vsi_type_id[1] << 8 |
			    pvsi->vsi_type_id[0];
			vsi->vsi_mgrid = pvsi->vsi_mgr_id;
			vsi->vsi_typeversion = pvsi->vsi_type_version;
			vsi->vsi_typeid = tid;
		}
		if (tb3[IFLA_PORT_INSTANCE_UUID]) {
			unsigned char *uuid = (unsigned char *)
				RTA_DATA(tb3[IFLA_PORT_INSTANCE_UUID]);
			memcpy(vsi->vsi_uuid, uuid, sizeof vsi->vsi_uuid);
		}
		if (tb3[IFLA_PORT_REQUEST])
			vsi->request =
				*(uint8_t *) RTA_DATA(tb3[IFLA_PORT_REQUEST]);
		if (tb3[IFLA_PORT_RESPONSE])
			vsi->response =
				*(uint16_t *) RTA_DATA(tb3[IFLA_PORT_RESPONSE]);
	}
	return 0;
}

/*
 * Parse the IFLA_VFINFO_LIST block of the netlink message.
 * Return zero on success and errno else.
 */
static int vdpnl_vfinfolist(struct nlattr *vfinfolist, struct vdpnl_vsi *vsi)
{
	struct nlattr *le1, *vf[IFLA_VF_MAX + 1];
	int rem;

	if (!vfinfolist) {
		LLDPAD_ERR("%s:IFLA_VFINFO_LIST missing\n", __func__);
		return -EINVAL;
	}
	nla_for_each_nested(le1, vfinfolist, rem) {
		bool have_mac = false, have_vid = false;

		if (nla_type(le1) != IFLA_VF_INFO) {
			LLDPAD_ERR("%s:parsing of IFLA_VFINFO_LIST failed\n",
				   __func__);
			return -EINVAL;
		}
		if (nla_parse_nested(vf, IFLA_VF_MAX, le1, ifla_vf_policy)) {
			LLDPAD_ERR("%s:parsing of IFLA_VF_INFO failed\n",
				   __func__);
			return -EINVAL;
		}

		if (vf[IFLA_VF_MAC]) {
			struct ifla_vf_mac *mac = RTA_DATA(vf[IFLA_VF_MAC]);

			memcpy(vsi->maclist->mac, mac->mac, ETH_ALEN);
			have_mac = true;
		}

		if (vf[IFLA_VF_VLAN]) {
			struct ifla_vf_vlan *vlan = RTA_DATA(vf[IFLA_VF_VLAN]);

			vsi->maclist->vlan = vlan->vlan;
			vsi->maclist->qos = vlan->qos;
			have_vid = true;
		}
		LLDPAD_DBG("%s:have_vid:%d have_mac:%d\n", __func__, have_vid,
			   have_mac);
		if (have_vid && have_mac)
			vsi->filter_fmt = VDP22_FFMT_MACVID;
		else if (have_vid)
			vsi->filter_fmt = VDP22_FFMT_VID;
		else
			return -EINVAL;
	}
	return 0;
}

/*
 * Convert the SETLINK message into internal data structure.
 */
static int vdpnl_set(struct nlmsghdr *nlh, struct vdpnl_vsi *vsi)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);
	int rc;

	if (nlmsg_parse(nlh, sizeof(struct ifinfomsg),
			(struct nlattr **)&tb, IFLA_MAX, NULL)) {
		LLDPAD_ERR("%s:error parsing SETLINK request\n", __func__);
		return -EINVAL;
	}

	vsi->ifindex = ifinfo->ifi_index;
	if (tb[IFLA_IFNAME])
		STRNCPY_TERMINATED(vsi->ifname, (char *)RTA_DATA(tb[IFLA_IFNAME]),
			sizeof vsi->ifname);
	else {
		if (!if_indextoname(ifinfo->ifi_index, vsi->ifname)) {
			LLDPAD_ERR("%s:can not find name for interface %i\n",
				   __func__, ifinfo->ifi_index);
			return -ENXIO;
		}
	}
	vsi->req_pid = nlh->nlmsg_pid;
	vsi->req_seq = nlh->nlmsg_seq;
	rc = vdpnl_vfinfolist(tb[IFLA_VFINFO_LIST], vsi);
	if (!rc) {
		rc = vdpnl_vfports(tb[IFLA_VF_PORTS], vsi);
		if (!rc)
			vdpnl_show(vsi);
	}
	return rc;
}

/*
 * Return the error code (can be zero) to the sender. Assume buffer is
 * large enough to hold the information.
 * Construct the netlink response on the input buffer.
 */
static int vdpnl_error(int err, struct nlmsghdr *from, size_t len)
{
	struct nlmsgerr nlmsgerr;

	LLDPAD_DBG("%s:error %d\n", __func__, err);
	nlmsgerr.error = err;
	nlmsgerr.msg = *from;
	memset(from, 0, len);
	from->nlmsg_type = NLMSG_ERROR;
	from->nlmsg_seq = nlmsgerr.msg.nlmsg_seq;
	from->nlmsg_pid = nlmsgerr.msg.nlmsg_pid;
	from->nlmsg_flags = 0;
	from->nlmsg_len = NLMSG_SPACE(sizeof nlmsgerr);
	memcpy(NLMSG_DATA(from), &nlmsgerr, sizeof nlmsgerr);
	return from->nlmsg_len;
}

/*
 * Build the variable part of the netlink reply message for status inquiry.
 * It contains the UUID and the response field for the VSI profile.
 */
static void vdpnl_reply2(struct vdpnl_vsi *p, struct nl_msg *nlh)
{
	char instance[VDP_UUID_STRLEN + 2];

	nla_put(nlh, IFLA_PORT_INSTANCE_UUID, sizeof p->vsi_uuid,
		  p->vsi_uuid);
	vdp_uuid2str(p->vsi_uuid, instance, sizeof instance);
	LLDPAD_DBG("%s:IFLA_PORT_INSTANCE_UUID:%s\n", __func__, instance);
	nla_put_u32(nlh, IFLA_PORT_VF, PORT_SELF_VF);
	LLDPAD_DBG("%s:IFLA_PORT_VF:%d\n", __func__,  PORT_SELF_VF);
	if (p->response != VDP_RESPONSE_NO_RESPONSE) {
		nla_put_u16(nlh, IFLA_PORT_RESPONSE, p->response);
		LLDPAD_DBG("%s:IFLA_PORT_RESPONSE:%d\n", __func__,
			   p->response);
	}
}

/*
 * Return bytes needed for one VSI in a netlink message.
 */
static size_t vdp_nllen(void)
{
	size_t needed;

	needed = nla_total_size(sizeof(struct nlattr)) /* IFLA_VF_PORT */
		+ nla_total_size(4) /* IFLA_PORT_VF */
		+ nla_total_size(PORT_UUID_MAX) /* IFLA_PORT_INSTANCE_UUID */
		+ nla_total_size(2); /* IFLA_PORT_RESPONSE */
	return needed;
}

/*
 * Get interface name (either from netlink message for from ifi_index).
 * Return error when no interface available.
 */
static int vdpnl_ifname(struct vdpnl_vsi *p, struct nlattr *tb)
{
	int rc = 0;

	if (tb)
		nla_strlcpy(p->ifname, tb, sizeof(p->ifname));
	else if (!if_indextoname(p->ifindex, p->ifname)) {
		LLDPAD_ERR("%s:ifindex %d without interface name\n", __func__,
			   p->ifindex);
		rc = -EINVAL;
	}
	return rc;
}

/*
 * Parse a received netlink request message and return a filled VSI data
 * structure.
 */
static struct nla_policy  pc_max[IFLA_MAX + 1] = {
	[IFLA_IFNAME] = {
				.minlen = 1,
				.maxlen = IFNAMSIZ + 1,
				.type = NLA_STRING
			}
};

/*
 * Retrieve name of interface and its index value from the netlink messaage
 * and store it in the data structure.
 * The GETLINK message may or may not contain the IFLA_IFNAME attribute.
 * Return 0 on success and errno on error.
 */
static int vdpnl_get(struct vdpnl_vsi *p, struct nlmsghdr *nlh)
{
	int rc;
	struct nlattr *tb[IFLA_MAX + 1];
	struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);

	memset(tb, 0, sizeof(tb));
	rc = nla_parse(tb, sizeof(tb) / sizeof(tb[0]),
			 (struct nlattr *)IFLA_RTA(NLMSG_DATA(nlh)),
			 IFLA_PAYLOAD(nlh), pc_max);
	if (rc) {
		LLDPAD_ERR("%s:error parsing GETLINK request\n", __func__);
		return -EINVAL;
	}
	p->ifindex = ifinfo->ifi_index;
	return vdpnl_ifname(p, tb[IFLA_IFNAME]);
}

/*
 * Delete the OUI structures of VSI22
 */

void vsinl_delete_oui(struct vdpnl_vsi *p)
{
	if ((p->ouisz == 0) || (p->oui_list == NULL))
		return;
	p->ouisz = 0;
	free(p->oui_list);
	p->oui_list = NULL;
}

/*
 * Free an malloc'ed maclist array.
 */
void vdp22_freemaclist(struct vdpnl_vsi *vsi)
{
	vsi->macsz = 0;
	free(vsi->maclist);
	vsi->maclist = NULL;
}

/*
 * Extract the interface name and loop over all VSI profile entries.
 * Find UUID and response field for each active profile and construct a
 * netlink response message.
 *
 * Return message size.
 */
static int vdpnl_getlink(struct nlmsghdr *nlh, size_t len)
{
	struct nlmsghdr *nlh_new;
	struct nl_msg *msg;
	struct vdpnl_vsi p;
	int i = 0, rc = -ENOMEM;
	struct nlattr *vf_ports, *vf_port;
	struct ifinfomsg ifinfo;
	size_t mylen = nla_total_size(sizeof(struct ifinfomsg))
			+ nla_total_size(sizeof(struct nlattr));
			/* Header + IFLA_VF_PORTS */

	mylen = nlmsg_total_size(mylen);
	memset(&ifinfo, 0, sizeof ifinfo);
	memset(&p, 0, sizeof p);
	msg = nlmsg_alloc_size(len);
	if (msg)
		rc = vdpnl_get(&p, nlh);
	if (rc) {
		nlmsg_free(msg);
		return vdpnl_error(rc, nlh, len);
	}
	nlmsg_put(msg, nlh->nlmsg_pid, nlh->nlmsg_seq, NLMSG_DONE, 0, 0);
	ifinfo.ifi_index = p.ifindex;
	nlmsg_append(msg, &ifinfo, sizeof(ifinfo), 0);

	vf_ports = nla_nest_start(msg, IFLA_VF_PORTS);
	/* Iterate over all profiles */
	do {
		rc = vdp22_query(p.ifname) ? vdp22_status(++i, &p, 0)
					   : vdp_status(++i, &p);
		mylen += vdp_nllen();
		if (rc == 1 && mylen < len) {
			vf_port = nla_nest_start(msg, IFLA_VF_PORT);
			vdpnl_reply2(&p, msg);
			nla_nest_end(msg, vf_port);
		}
		vdp22_freemaclist(&p);
		vsinl_delete_oui(&p);
	} while (rc == 1);
	nla_nest_end(msg, vf_ports);
	if (rc < 0) {
		nlmsg_free(msg);
		return vdpnl_error(rc, nlh, len);
	}
	nlh_new = nlmsg_hdr(msg);
	rc = nlh_new->nlmsg_len;
	memcpy((unsigned char *)nlh, nlh_new, rc);
	nlmsg_free(msg);
	LLDPAD_DBG("%s:message-size:%d\n", __func__, rc);
	return rc;
}

/*
 * Parse incoming command and create a data structure to store the VSI data.
 */
static int vdpnl_setlink(struct nlmsghdr *nlh, size_t len)
{
	int rc = -ENOMEM;
	struct vdpnl_mac mac;
	struct vdpnl_vsi p;

	memset(&p, 0, sizeof p);
	memset(&mac, 0, sizeof mac);
	p.vsi_idfmt = VDP22_ID_UUID;
	p.macsz = 1;
	p.maclist = &mac;
	rc = vdpnl_set(nlh, &p);
	if (!rc)
		rc = vdp22_query(p.ifname) ? vdp22_request(&p, 0)
					   : vdp_request(&p);
	return vdpnl_error(rc, nlh, len);
}

/*
 * Process the netlink message. Parameters are the socket, the message and
 * its length in bytes.
 * The message buffer 'buf' is used for parsing the incoming message.
 * After parsing and decoding, the outgoing message is stored in 'buf'.
 *
 * Returns:
 *  < 0: Errno number when message parsing failed.
 *  == 0: Message ok and no response.
 *  > 0: Message ok and response returned in buf parameter. Returns bytes
 *       of response.
 */
int vdpnl_recv(unsigned char *buf, size_t buflen)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	LLDPAD_DBG("%s:buflen:%zd nlh.nl_pid:%d nlh_type:%d nlh_seq:%d "
		   "nlh_len:%d\n", __func__, buflen, nlh->nlmsg_pid,
		   nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_len);

	switch (nlh->nlmsg_type) {
	case RTM_SETLINK:
		return vdpnl_setlink(nlh, buflen);
	case RTM_GETLINK:
		return vdpnl_getlink(nlh, buflen);
	default:
		LLDPAD_ERR("%s:unknown type %d\n", __func__, nlh->nlmsg_type);
	}
	return -ENODEV;
}

/*
 * Add one entry in the list of MAC,VLAN pairs.
 */
static void add_pair(struct vdpnl_mac *mac, struct nl_msg *nlh)
{
	struct nlattr *vfinfo;
	struct ifla_vf_mac ifla_vf_mac = {
		.vf = PORT_SELF_VF,
		.mac = { 0, }
	};
	struct ifla_vf_vlan ifla_vf_vlan = {
		.vf = PORT_SELF_VF,
		.vlan = mac->vlan,
		.qos = mac->qos
	};

	vfinfo = nla_nest_start(nlh, IFLA_VF_INFO);
	memcpy(ifla_vf_mac.mac, mac->mac, sizeof mac->mac);
	nla_put(nlh, IFLA_VF_MAC, sizeof ifla_vf_mac, &ifla_vf_mac);
	nla_put(nlh, IFLA_VF_VLAN, sizeof ifla_vf_vlan, &ifla_vf_vlan);
	nla_nest_end(nlh, vfinfo);
}

/*
 * Walk along the MAC,VLAN ID list and add each entry into the message.
 */
static void add_mac_vlan(struct vdpnl_vsi *vsi, struct nl_msg *nlh)
{
	struct nlattr *vfinfolist;
	int i;

	vfinfolist = nla_nest_start(nlh, IFLA_VFINFO_LIST);
	for (i = 0; i < vsi->macsz; ++i)
		add_pair(&vsi->maclist[i], nlh);
	nla_nest_end(nlh, vfinfolist);
}

/*
 * Build an unsolicited netlink message to the VSI requestor. The originator
 * is the switch abondoning the VSI profile.
 * Assumes the messages fits into an 4KB buffer.
 * Returns the message size in bytes.
 */
int vdpnl_send(struct vdpnl_vsi *vsi)
{
	struct nlmsghdr *nlh;
	struct nlattr *vf_ports, *vf_port;
	struct ifinfomsg ifinfo;
	struct ifla_port_vsi portvsi;
	struct nl_msg *msg;
	int rc = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		LLDPAD_DBG("%s:%s error allocating netlink message memory:\n",
			   __func__, vsi->ifname);
		return rc;
	}
	nlmsg_put(msg, getpid(), vsi->req_seq, RTM_SETLINK, 0, 0);

	memset(&ifinfo, 0, sizeof ifinfo);
	ifinfo.ifi_index = vsi->ifindex;
	nlmsg_append(msg, &ifinfo, sizeof(ifinfo), 0);
	nla_put_string(msg, IFLA_IFNAME, vsi->ifname);

	add_mac_vlan(vsi, msg);
	portvsi.vsi_mgr_id = vsi->vsi_mgrid;
	portvsi.vsi_type_id[0] = vsi->vsi_typeid & 0xff;
	portvsi.vsi_type_id[1] = (vsi->vsi_typeid >> 8) & 0xff;
	portvsi.vsi_type_id[2] = (vsi->vsi_typeid >> 16) & 0xff;
	portvsi.vsi_type_version = vsi->vsi_typeversion;
	vf_ports = nla_nest_start(msg, IFLA_VF_PORTS);
	vf_port = nla_nest_start(msg, IFLA_VF_PORT);
	nla_put(msg, IFLA_PORT_VSI_TYPE, sizeof portvsi, &portvsi);
	nla_put(msg, IFLA_PORT_INSTANCE_UUID, PORT_UUID_MAX, vsi->vsi_uuid);
	nla_put_u32(msg, IFLA_PORT_VF, PORT_SELF_VF);
	nla_put_u16(msg, IFLA_PORT_REQUEST, vsi->request);
	nla_nest_end(msg, vf_port);
	nla_nest_end(msg, vf_ports);
	vdpnl_show(vsi);
	nlh = nlmsg_hdr(msg);
	LLDPAD_DBG("%s:nlh.nl_pid:%d nlh_type:%d nlh_seq:%d nlh_len:%d\n",
		    __func__, nlh->nlmsg_pid, nlh->nlmsg_type, nlh->nlmsg_seq,
		    nlh->nlmsg_len);
	rc = event_trigger(nlh, vsi->req_pid);
	nlmsg_free(msg);
	return rc;
}
