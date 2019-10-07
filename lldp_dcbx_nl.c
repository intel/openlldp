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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "linux/dcbnl.h"
#include "lldp.h"
#include "lldp_util.h"
#include "dcb_types.h"
#include "dcb_protocol.h"
#include "dcb_driver_interface.h"
#include "lldp_dcbx_nl.h"
#include "messages.h"
#include "lldp_rtnl.h"
#include "lldp/ports.h"

static int nl_sd = 0;
static int rtseq = 0;

static int next_rtseq(void)
{
	return ++rtseq;
}

static int init_socket(void)
{
	int sd;
	int rcv_size = MAX_MSG_SIZE;
	struct sockaddr_nl snl;
	int reuse = 1;

	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sd < 0)
		return sd;

	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int)) < 0) {
		close(sd);
		return -EIO;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
		close(sd);
		return -EIO;
	}

	memset((void *)&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = 0;

	if (connect(sd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
		close(sd);
		return -EIO;
	}

	return sd;
}

static struct nlmsghdr *start_msg(__u16 msg_type, __u8 arg)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct ifinfomsg *ifi;

	/* nlh needs to be free'd by send_msg() */
	nlh = (struct nlmsghdr *)malloc(MAX_MSG_SIZE);
	if (NULL == nlh)
		return NULL;
	memset((void *)nlh, 0, MAX_MSG_SIZE);


	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = next_rtseq();
	nlh->nlmsg_pid = getpid();

	switch (msg_type) {
	case RTM_GETDCB:
	case RTM_SETDCB:
		nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct dcbmsg));
		d = NLMSG_DATA(nlh);
		d->cmd = arg;
		d->dcb_family = AF_UNSPEC;
		d->dcb_pad = 0;
		break;
	case RTM_GETLINK:
		nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		ifi = NLMSG_DATA(nlh);
		ifi->ifi_family = AF_UNSPEC;
		ifi->ifi_index = arg;
		ifi->ifi_change = 0xffffffff;
		break;
	default:
		free(nlh);
		nlh = NULL;
		break;
	}

	return nlh;
}

static struct rtattr *add_rta(struct nlmsghdr *nlh, __u16 rta_type,
                              void *attr, __u16 rta_len)
{
	struct rtattr *rta;

	rta = (struct rtattr *)((char *)nlh + nlh->nlmsg_len);
	rta->rta_type = rta_type;
	rta->rta_len = rta_len + NLA_HDRLEN;
	if (attr)
		memcpy(NLA_DATA(rta), attr, rta_len);
	nlh->nlmsg_len += NLMSG_ALIGN(rta->rta_len);

	return rta;
}

/* free's nlh which was allocated by start_msg */
static int send_msg(struct nlmsghdr *nlh)
{
	struct sockaddr_nl nladdr;
	void *buf = (void *)nlh;
	int r, len = nlh->nlmsg_len;

	if (nlh == NULL)
		return 1;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	
	do {
		r = sendto(nl_sd, buf, len, 0, (struct sockaddr *)&nladdr,
			sizeof(nladdr));
		LLDPAD_DBG("send_msg: sendto = %d\n", r);

	} while (r < 0 && errno == EINTR);

	free(nlh);

	if (r < 0)
		return 1;
	else
		return 0;
}

static struct nlmsghdr *get_msg(unsigned int seq)
{
	struct nlmsghdr *nlh;
	unsigned len;
	int res;
	int found = 0;

	/* nlh needs to be free'd by caller */
	nlh = (struct nlmsghdr *)malloc(MAX_MSG_SIZE);
	if (NULL == nlh)
		return NULL;
	memset(nlh, 0, MAX_MSG_SIZE);

	while (!found) {
		res = recv(nl_sd, (void *)nlh, MAX_MSG_SIZE, MSG_DONTWAIT);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("get_msg: recv error");
			free(nlh);
			nlh = NULL;
			break;
		}
		len = res;
		if (!(NLMSG_OK(nlh, len))) {
			LLDPAD_DBG("get_msg: NLMSG_OK is false\n");
			free(nlh);
			nlh = NULL;
			break;
		}
		if ((nlh->nlmsg_type == RTM_GETDCB ||
			nlh->nlmsg_type == RTM_SETDCB) &&
			nlh->nlmsg_seq == seq) {
			break;
		} else if (nlh->nlmsg_type == NLMSG_ERROR) {
			if (nlh->nlmsg_seq != seq) {
				continue;
			} else {
				free(nlh);
				nlh = NULL;
				break;
			}
			break;
		}
	}

	return nlh;
}

static int recv_msg(int cmd, int attr, unsigned int seq)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;
	int rval;

	nlh = get_msg(seq);

	if (NULL == nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if ((d->cmd != cmd) || (rta->rta_type != attr)) {
		LLDPAD_DBG("Bad netlink message attribute.");
		return -EIO;
	}

	rval = *(__u8 *)NLA_DATA(rta);
	free(nlh);
	return rval;
}

static int get_state(char *ifname, __u8 *state)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;
	int rval = 0;
	unsigned int seq;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GSTATE);

	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg(seq);
	if (NULL == nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GSTATE) {
		return -EIO;
	}
	if (rta->rta_type != DCB_ATTR_STATE) {
		rval = -EIO;
	} else {
		*state = *(__u8 *)NLA_DATA(rta);
	}

	free(nlh);

	return rval;
}

static int set_state(char *ifname, __u8 state)
{
	struct nlmsghdr *nlh;
	int seq;

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SSTATE);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_STATE, (void *)&state, sizeof(__u8));

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_SSTATE, DCB_ATTR_STATE, seq));
}


/* returns: 0 on success
 *          non-zero on failure
*/
static int set_pfc_cfg(char *ifname, __u8 *pfc)
{
	struct nlmsghdr *nlh;
	struct rtattr *rta_parent, *rta_child;
	int i;
	int seq;

	LLDPAD_DBG("set_pfc_cfg: %s\n", ifname);
	nlh = start_msg(RTM_SETDCB, DCB_CMD_PFC_SCFG);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_PFC_CFG, NULL, 0);
	for (i = DCB_PFC_UP_ATTR_0; i < DCB_PFC_UP_ATTR_MAX; i++) {
		rta_child = add_rta(nlh, i, (void *)pfc, sizeof(__u8));
		rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);
		pfc++;
	}

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_PFC_SCFG, DCB_ATTR_PFC_CFG, seq));
}

/* returns: 0 on success
 *          non-zero on failure
*/
static int set_pfc_state(char *ifname, __u8 state)
{
	struct nlmsghdr *nlh;
	int seq;

	LLDPAD_DBG("set_pfc_state: %s\n", ifname);
	nlh = start_msg(RTM_SETDCB, DCB_CMD_PFC_SSTATE);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_PFC_STATE, (void *)&state, sizeof(__u8));

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_PFC_SSTATE, DCB_ATTR_PFC_STATE, seq));
	return 0;
}
/* returns: 0 on success
 *          1 on failure
*/
static int set_pg_cfg(char *ifname, struct tc_config *tc, __u8 *bwg, int cmd)
{
	struct nlmsghdr *nlh;
	struct rtattr *class_parent, *param_parent, *rta_child;
	__u8 *p = (__u8 *)tc;
	__u8 *b = (__u8 *)bwg;
	int i, j;
	int seq;

	nlh = start_msg(RTM_SETDCB, cmd);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	class_parent = add_rta(nlh, DCB_ATTR_PG_CFG, NULL, 0);
	for (i = DCB_PG_ATTR_TC_0; i < DCB_PG_ATTR_TC_MAX; i++) {
		param_parent = add_rta(nlh, i, NULL, 0);
		for (j = DCB_TC_ATTR_PARAM_UNDEFINED + 1;
			j < DCB_TC_ATTR_PARAM_MAX; j++) {
			rta_child = add_rta(nlh, j, (void *)p, sizeof(__u8));
			param_parent->rta_len += NLA_ALIGN(rta_child->rta_len);
			p++;
		}
		class_parent->rta_len += NLA_ALIGN(param_parent->rta_len);
	}
	for (i = DCB_PG_ATTR_BW_ID_0; i < DCB_PG_ATTR_BW_ID_MAX; i++) {
		rta_child = add_rta(nlh, i, (void *)b, sizeof(__u8));
		class_parent->rta_len += NLA_ALIGN(rta_child->rta_len);
		b++;
	}

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(cmd, DCB_ATTR_PG_CFG, seq));
}


/* returns 0: on error initializing interface
 *         1: if successful
*/
int init_drv_if(void)
{
	int err = 0;

	if ((nl_sd = init_socket()) < 0) {
		LLDPAD_ERR("Error creating Netlink socket\n");
		return err;
	}
	return 1;
}

int deinit_drv_if(void)
{
	int rc;

	rc = fcntl(nl_sd, F_GETFD);
	if (rc != -1) {
		rc = close(nl_sd);
		if (rc)
			LLDPAD_ERR("Failed to close NETLINK socket (%d)\n",
					rc);
		nl_sd = 0;
	}
	return 0;
}
		

int set_dcbx_mode(char *ifname, __u8 mode)
{
	struct nlmsghdr *nlh;
	int seq;

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SDCBX);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_DCBX, (void *)&mode, sizeof(__u8));

	if (send_msg(nlh))
		return -EIO;

	return recv_msg(DCB_CMD_SDCBX, DCB_ATTR_DCBX, seq);
}

int get_dcb_capabilities(char *ifname,
	struct feature_support *dcb_capabilities)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent;
	struct rtattr *rta_child;
	int rval = 0;
	unsigned int seq;
	int i;
	u8 cap;

	memset((char *)dcb_capabilities, 0, sizeof(struct feature_support));

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GCAP);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_CAP, NULL, 0);

	rta_child = add_rta(nlh, DCB_CAP_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg(seq);
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GCAP)
		return -EIO;

	if (rta_parent->rta_type != DCB_ATTR_CAP)
		return -EIO;

	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));

	for (i = 0; rta_parent > rta_child; i++) {
		cap = *(u8 *)NLA_DATA(rta_child);

		switch (rta_child->rta_type) {
		case DCB_CAP_ATTR_PG:
			dcb_capabilities->pg = cap;
			break;
		case DCB_CAP_ATTR_PFC:
			dcb_capabilities->pfc = cap;
			break;
		case DCB_CAP_ATTR_UP2TC:
			dcb_capabilities->up2tc_mappable = cap;
			break;
		case DCB_CAP_ATTR_PG_TCS:
			dcb_capabilities->traffic_classes = cap;
			break;
		case DCB_CAP_ATTR_PFC_TCS:
			dcb_capabilities->pfc_traffic_classes = cap;
			break;
		case DCB_CAP_ATTR_GSP:
			dcb_capabilities->gsp = cap;
			break;
		case DCB_CAP_ATTR_DCBX:
			dcb_capabilities->dcbx = cap;
			break;
		default:
			LLDPAD_DBG("unknown capability %d: %02x\n",
				rta_child->rta_type, cap);
			break;
		}

		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));
	}
	if (rta_parent != rta_child)
		LLDPAD_DBG("rta pointers are off\n");

	free(nlh);
	return rval;
}

int get_dcb_numtcs(const char *ifname, u8 *pgtcs, u8 *pfctcs)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent;
	struct rtattr *rta_child;
	int rval = 0;
	unsigned int seq;
	int i;
	int found;
	char name[IFNAMSIZ];

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GNUMTCS);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;

	STRNCPY_TERMINATED (name, ifname, sizeof(name));
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)name, strlen(name) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_NUMTCS, NULL, 0);

	rta_child = add_rta(nlh, DCB_NUMTCS_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg(seq);
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GNUMTCS)
		return -EIO;

	if (rta_parent->rta_type != DCB_ATTR_NUMTCS)
		return -EIO;

	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));

	found = 0;
	for (i = 0; rta_parent > rta_child; i++) {
		switch (rta_child->rta_type) {
		case DCB_NUMTCS_ATTR_PG:
			if (! (found & 0x01) ) {
				*pgtcs = *(u8 *)NLA_DATA(rta_child);
				found += 1;
			}
			break;
		case DCB_NUMTCS_ATTR_PFC:
			if (!(found & 0x02)) {
				*pfctcs = *(u8 *)NLA_DATA(rta_child);
				found += 2;
			}
			break;
		default:
			LLDPAD_DBG("unknown capability %d: %02x\n",
				rta_child->rta_type,
				*(u8 *)NLA_DATA(rta_child));
			break;
		}

		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));
	}
	if (rta_parent != rta_child)
		LLDPAD_DBG("rta pointers are off\n");

	free(nlh);
	if (found != 3)
		rval = -EIO;
	return rval;
}


int get_hw_state(char *ifname, int *dcb_state)
{
	int err = 0;
	__u8 state = 0;

	err = get_state(ifname, &state);
	if (err)
		LLDPAD_INFO("Adapter %s does not support DCB.\n", ifname);
	else
		LLDPAD_DBG("Adapter %s supports DCB.\n", ifname);

	*dcb_state = state;

	return err;
}
	
int set_hw_state(char *ifname, int dcb_state)
{
	int err;
	int ifindex = get_ifidx(ifname);

	err = set_linkmode(ifindex, ifname, dcb_state);

	if (err)
		LLDPAD_DBG("ERROR %s: set_linkmode dcbstate %i\n",
			__func__, dcb_state);

	return set_state(ifname, (__u8)dcb_state);
}
	
/* returns:  0 on success
 *           1 on failure
*/
int set_hw_pg(char *ifname, pgroup_attribs *pg_data, bool oper_mode)
{
	int i, j;
	int rval = 0;
	struct tc_config tc[MAX_TRAFFIC_CLASSES];
	__u8 bwg[MAX_BANDWIDTH_GROUPS];
	pg_attribs        pg_df_store;
	pgroup_attribs    pg_df_data, *pg_temp;

	if (!oper_mode) { /* oper mode is false */
		get_pg(DEF_CFG_STORE, &pg_df_store);
		memcpy(&pg_df_data.rx, &pg_df_store.rx, sizeof(pg_df_data.rx));
		memcpy(&pg_df_data.tx, &pg_df_store.tx, sizeof(pg_df_data.tx));
		pg_temp = &pg_df_data;
	} else {
		pg_temp = pg_data;
	}

	/* Configure TX PG per TC Settings */
	for (i = 0; i < MAX_TRAFFIC_CLASSES; i++)
		tc[i].up_to_tc_bitmap = 0;

	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		for (j = 0; j < MAX_TRAFFIC_CLASSES; j++) {
			if (pg_temp->tx.up[i].pgid == j) {
				tc[j].up_to_tc_bitmap |= (1 << i);
				tc[j].prio_type = pg_temp->tx.up[i].strict_priority;
				tc[j].tc_percent = pg_temp->tx.up[i].percent_of_pg_cap;
			}
		}
	}

	for (i = 0; i < MAX_TRAFFIC_CLASSES; i++) {
		tc[i].bwgid = pg_temp->tx.up[i].bwgid;
		bwg[i] = pg_temp->tx.pg_percent[i];
		LLDPAD_DBG("%s %s: (%i) TX bwgid %i up_to_tc %i "
			   "prio %i percent %i\n",
			    __func__, ifname, i,
			    tc[i].bwgid,
			    tc[i].up_to_tc_bitmap,
			    tc[i].prio_type,
			    tc[i].tc_percent);
	}
	rval = set_pg_cfg(ifname, &tc[0], &bwg[0], DCB_CMD_PGTX_SCFG);

	/* Configure RX PG per TC Settings */
	for (i = 0; i < MAX_TRAFFIC_CLASSES; i++)
		tc[i].up_to_tc_bitmap = 0;

	for (i = 0; i < MAX_USER_PRIORITIES; i++) {
		for (j = 0; j < MAX_TRAFFIC_CLASSES; j++) {
			if (pg_temp->tx.up[i].pgid == j) {
				tc[j].up_to_tc_bitmap |= (1 << i);
				tc[j].prio_type = pg_temp->rx.up[i].strict_priority;
				tc[j].tc_percent = pg_temp->rx.up[i].percent_of_pg_cap;
			}
		}
	}

	for (i = 0; i < MAX_TRAFFIC_CLASSES; i++) {
		tc[i].bwgid = pg_temp->rx.up[i].bwgid;
		bwg[i] = pg_temp->rx.pg_percent[i];
		LLDPAD_DBG("%s %s: (%i) RX bwgid %i up_to_tc %i "
			   "prio %i percent %i\n",
			   __func__, ifname, i,
			   tc[i].bwgid,
			   tc[i].up_to_tc_bitmap,
			   tc[i].prio_type,
			   tc[i].tc_percent);
	}
	rval |= set_pg_cfg(ifname, &tc[0], &bwg[0], DCB_CMD_PGRX_SCFG);
	return rval;
}

/* returns:  0 on success
 *           non-zero on failure
*/
int set_hw_pfc(char *ifname, dcb_pfc_list_type pfc_data,
	bool oper_mode)
{
	int i;
	__u8 pfc[MAX_TRAFFIC_CLASSES];
	pfc_attribs             pfc_df_store;
	pfc_type                *pfc_temp;
	int rval;

	if (!oper_mode) /* oper mode is false */
	{
		get_pfc(DEF_CFG_STORE, &pfc_df_store);
		pfc_temp = pfc_df_store.admin;
	} else {
		pfc_temp = pfc_data;
	}

	for (i = 0; i < MAX_TRAFFIC_CLASSES; i++) {
		if (pfc_temp[i])
			pfc[i] = PFC_ENABLED;
		else
			pfc[i] = PFC_DISABLED;
	}

	rval = set_pfc_cfg(ifname, &pfc[0]);
	if (!rval)
		rval = set_pfc_state(ifname, (__u8)oper_mode);
	return rval;
}

/* returns: 0 on success
 *          1 on failure
*/
int set_hw_app(char *ifname, appgroup_attribs *app_data)
{
	struct nlmsghdr *nlh;
	struct rtattr *rta_parent, *rta_child;
	int seq;

	LLDPAD_DBG("set_hw_app: %s\n", ifname);

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SAPP);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_APP, NULL, 0);

	rta_child = add_rta(nlh, DCB_APP_ATTR_IDTYPE, 
		(void *)&app_data->dcb_app_idtype, sizeof(__u8));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_APP_ATTR_ID, 
		(void *)&app_data->dcb_app_id, sizeof(__u16));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_APP_ATTR_PRIORITY, 
		(void *)&app_data->dcb_app_priority, sizeof(__u8));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_SAPP, DCB_ATTR_APP, seq));
}

int set_hw_all(char *ifname)
{
	struct nlmsghdr *nlh;
	int status = 1; /* status is always true */
	int retval = -EIO;
	int seq;

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SET_ALL);
	if (NULL == nlh)
		return -EIO;

	seq = nlh->nlmsg_seq;
	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_SET_ALL, (void *)&status, sizeof(__u8));

	if (send_msg(nlh))
		return -EIO;

	retval = recv_msg(DCB_CMD_SET_ALL, DCB_ATTR_SET_ALL, seq);

	/* driver will respond with 
	 * 0 = hw config changes made - with link reset
	 * 1 = no hw config changes were necessary
	 * 2 = hw config changes made - with no link reset
	*/
	if (retval == 0)
		set_port_hw_resetting(ifname, 1);

	return 0;
}

bool check_port_dcb_mode(char *ifname)
{
	int dcb_state = 0;

	if (get_hw_state(ifname, &dcb_state))
		dcb_state = 0;
	if (dcb_state) {
		LLDPAD_DBG("config.c: %s dcb mode is ON.\n", ifname);
		return true;
	} else {
		LLDPAD_DBG("config.c: %s dcb mode is OFF. \n", ifname);
		return false;
	}
}
