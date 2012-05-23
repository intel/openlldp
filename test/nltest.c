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

#include <errno.h>
#include <unistd.h>
#include "nltest.h"

#define MAX_ADDR_LEN 32  /* instead of including linux/netdevice.h */

#ifdef DCB_APP_IDTYPE_ETHTYPE
#define DCB_APP_DRV_IF_SUPPORTED
#endif

#ifdef HEXDUMP
static void hexprint(char *b, int len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		if (i%16 == 0) printf("%s\t", i?"\n":"");
		printf("%02x ", (unsigned char)*(b + i));
	}
	printf("\n\n");
}
#endif

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int init_socket(void)
{
	int sd;
	int rcv_size = 8 * 1024;
	struct sockaddr_nl snl;

	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sd < 0)
		return sd;
  
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(int)) < 0) {
		close(sd);
		return -EIO;
	}
  
	memset((void *)&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;       
	snl.nl_pid = getpid(); 
	/* snl.nl_groups = RTMGRP_LINK; */
  
	if (bind(sd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
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

	nlh = (struct nlmsghdr *)malloc(MAX_MSG_SIZE);
	if (NULL==nlh)
		return NULL;
	memset((void *)nlh, 0, MAX_MSG_SIZE);
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;
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
		return NULL;
		break;
	}

	return nlh;

}

int addattr_l(struct nlmsghdr *n, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > MAX_MSG_SIZE) {
		fprintf(stderr, "addattr_l: message exceeded bound of %d\n",
			MAX_MSG_SIZE);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n",
			len, rta->rta_len);
	return 0;
}

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))

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

static int send_msg(struct nlmsghdr *nlh)
{
	struct sockaddr_nl nladdr;
	void *buf = (void *)nlh;
	int r, len = nlh->nlmsg_len;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	
	do {
#ifdef HEXDUMP
		printf("SENT A MESSAGE: %d\n", len);
		hexprint((char *)nlh, nlh->nlmsg_len);
#endif
		r = sendto(nl_sd, buf, len, 0, (struct sockaddr *)&nladdr,
			sizeof(nladdr));
	} while (r < 0 && errno == EINTR);

	if (r < 0) {
		printf("SEND FAILED: %d\n", r);
		return 1;
	}
	else
		return 0;
}

static struct nlmsghdr *get_msg(void)
{
	struct nlmsghdr *nlh;
	int len;

	nlh = (struct nlmsghdr *)malloc(MAX_MSG_SIZE);
	if (NULL==nlh)
		return NULL;
	memset(nlh, 0, MAX_MSG_SIZE);

	len = recv(nl_sd, (void *)nlh, MAX_MSG_SIZE, 0);

	if ((nlh->nlmsg_type == NLMSG_ERROR) || (len < 0) ||
	    !(NLMSG_OK(nlh, (unsigned int)len))) {
		free(nlh);
		printf("RECEIVE FAILED: %d\n", len);
#ifdef HEXDUMP
		if (len > 0)
			hexprint((char *)nlh, len);
#endif
		return NULL;
	}
#ifdef HEXDUMP
	printf("RECEIVED A MESSAGE: %d\n", len);
	hexprint((char *)nlh, nlh->nlmsg_len);
#endif

	return nlh;
}

static int recv_msg(int cmd, int attr)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;
	int rval;

	nlh = get_msg();

	if (NULL == nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if ((d->cmd != cmd) || (rta->rta_type != attr)) {
		printf("Bad netlink message attribute.");
		return -EIO;
	}

	rval = *(__u8 *)NLA_DATA(rta);
	free(nlh);
	return rval;
}
  
static int set_state(char *ifname, __u8 state)
{
	struct nlmsghdr *nlh;

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SSTATE);
	if (NULL == nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_STATE, (void *)&state, sizeof(__u8));

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_SSTATE, DCB_ATTR_STATE));
}

static int get_state(char *ifname, __u8 *state)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GSTATE);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);

	if (send_msg(nlh))
		return -EIO;

	free(nlh);

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GSTATE) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}
	if (rta->rta_type != DCB_ATTR_STATE) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}
	*state = *(__u8 *)NLA_DATA(rta);

	return 0;
}
 

static int get_pfc_cfg(char *ifname, __u8 *pfc)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int i;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_PFC_GCFG);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname,
	        strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_PFC_CFG, NULL, 0);

	rta_child = add_rta(nlh, DCB_PFC_UP_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_PFC_GCFG) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}
	if (rta_parent->rta_type != DCB_ATTR_PFC_CFG) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}
	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));
	for (i = 0; rta_parent > rta_child; i++) {
		if (i == 8) {
			printf("pfc array out of range\n");
			break;
		}
		pfc[rta_child->rta_type - DCB_PFC_UP_ATTR_0] = 
			*(__u8 *)NLA_DATA(rta_child);
		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));
	}
	if (rta_parent != rta_child)
		printf("rta pointers are off\n");

	return 0;
}

static int get_pfc_state(char *ifname, __u8 *state)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_PFC_GSTATE);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);

	if (send_msg(nlh))
		return -EIO;
	free(nlh);

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_PFC_GSTATE) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}

	if (rta->rta_type != DCB_ATTR_PFC_STATE) {
		return -EIO;
	}
	*state = *(__u8 *)NLA_DATA(rta);
	return 0;
}

static int get_pg(char *ifname, struct tc_config *tc, __u8 *bwg, int cmd)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *class_parent, *param_parent, *rta_child;
	__u8 *p = (__u8 *)tc;
	int i, j;

	nlh = start_msg(RTM_GETDCB, cmd);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	class_parent = add_rta(nlh, DCB_ATTR_PG_CFG, NULL, 0);
	param_parent = add_rta(nlh, DCB_PG_ATTR_TC_ALL, NULL, 0);
	rta_child = add_rta(nlh, DCB_TC_ATTR_PARAM_ALL, NULL, 0);
	param_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);
	class_parent->rta_len += NLMSG_ALIGN(param_parent->rta_len);

	rta_child = add_rta(nlh, DCB_PG_ATTR_BW_ID_ALL, NULL, 0);
	class_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);
	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	class_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != cmd) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}
	if (class_parent->rta_type != DCB_ATTR_PG_CFG) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}
	param_parent = NLA_DATA(class_parent);
	class_parent = (struct rtattr *)((char *)class_parent +
	                                 NLMSG_ALIGN(class_parent->rta_len));

	for (i = 0; class_parent > param_parent; i++) {
		if (param_parent->rta_type >= DCB_PG_ATTR_TC_0 &&
			param_parent->rta_type < DCB_PG_ATTR_TC_MAX) {
			rta_child = NLA_DATA(param_parent);
			param_parent = (struct rtattr *)((char *)param_parent +
			      NLMSG_ALIGN(param_parent->rta_len));

			for (j = 0; param_parent > rta_child; j++) {
				if (j == DCB_TC_ATTR_PARAM_MAX -
					DCB_TC_ATTR_PARAM_UNDEFINED + 1) {
					printf("parameter array out of "
						"range: %d\n", j);
					break;
				}
				*p = *(__u8 *)NLA_DATA(rta_child);
				rta_child =
					(struct rtattr *)((char *)rta_child +
					NLMSG_ALIGN(rta_child->rta_len));
				p++;
			}
			if (param_parent != rta_child) {
				printf("param_parent and rta_child pointers "
					"are off\n");
			}
		} else if (param_parent->rta_type >= DCB_PG_ATTR_BW_ID_0 &&
			param_parent->rta_type < DCB_PG_ATTR_BW_ID_MAX) {
			j = param_parent->rta_type - DCB_PG_ATTR_BW_ID_0;
			bwg[j] = *(__u8 *)NLA_DATA(param_parent);
			param_parent = (struct rtattr *)((char *)param_parent +
				NLMSG_ALIGN(param_parent->rta_len));
		}
		else
			printf("unknown param_parent type = %d\n",
				param_parent->rta_type);

	}

	if (class_parent != param_parent)
		printf("class_parent and param_parent pointers are off\n");

	return 0;
}

static int get_perm_hwaddr(char *ifname, __u8 *buf_perm, __u8 *buf_san)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GPERM_HWADDR);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_PERM_HWADDR, NULL, 0);
	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh) {
		printf("get msg failed\n");
		return -EIO;
	}

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GPERM_HWADDR) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}

	if (rta->rta_type != DCB_ATTR_PERM_HWADDR) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}

	memcpy(buf_perm, NLA_DATA(rta), ETH_ALEN);
	memcpy(buf_san, NLA_DATA(rta + ETH_ALEN*sizeof(__u8)), ETH_ALEN);

	return 0;
}
 
static int get_cap(char *ifname, __u8 *cap)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int i;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GCAP);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_CAP, NULL, 0);

	rta_child = add_rta(nlh, DCB_CAP_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GCAP) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}
	if (rta_parent->rta_type != DCB_ATTR_CAP) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}

	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));
	for (i = 0; rta_parent > rta_child; i++) {
		if (i == 8) {
			printf("cap array out of range\n");
			break;
		}

		cap[rta_child->rta_type] = *(__u8 *)NLA_DATA(rta_child);

		switch (rta_child->rta_type) {
		case DCB_CAP_ATTR_ALL:
			break;
		case DCB_CAP_ATTR_PG:
			printf("pg:      ");
			break;
		case DCB_CAP_ATTR_PFC:
			printf("pfc:     ");
			break;
		case DCB_CAP_ATTR_UP2TC:
			printf("up2tc:   ");
			break;
		case DCB_CAP_ATTR_PG_TCS:
			printf("pg tcs:  ");
			break;
		case DCB_CAP_ATTR_PFC_TCS:
			printf("pfc tcs: ");
			break;
		case DCB_CAP_ATTR_GSP:
			printf("gsp:     ");
			break;
		case DCB_CAP_ATTR_BCN:
			printf("bcn:     ");
			break;
		case DCB_CAP_ATTR_DCBX:
			printf("dcbx:    ");
			break;
		default:
			printf("unknown type: ");
			break;
		}
		printf("%02x\n", cap[rta_child->rta_type]);

		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));
	}
	if (rta_parent != rta_child)
		printf("rta pointers are off\n");

	return 0;
}

/* returns: 0 on success
 *          1 on failure
*/
static int set_numtcs(char *ifname, int tcid, __u8 numtcs)
{
	struct nlmsghdr *nlh;
	struct rtattr *rta_parent, *rta_child;

	printf("set_numtcs_cfg: %s\n", ifname);

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SNUMTCS);
	if (NULL == nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_NUMTCS, NULL, 0);
	rta_child = add_rta(nlh, tcid, &numtcs, sizeof(__u8));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_SNUMTCS, DCB_ATTR_NUMTCS));
}

static int get_numtcs(char *ifname, int tcid, __u8 *numtcs)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int found;
	int i;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GNUMTCS);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_NUMTCS, NULL, 0);

	rta_child = add_rta(nlh, DCB_NUMTCS_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GNUMTCS) {
		printf("Hmm, this is not the message we were expecting.\n");
		return -EIO;
	}
	if (rta_parent->rta_type != DCB_ATTR_NUMTCS) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		return -EIO;
	}
	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));

	found = 0;
	for (i = 0; rta_parent > rta_child; i++) {

		if (!found && rta_child->rta_type == tcid) {
			*numtcs = *(__u8 *)NLA_DATA(rta_child);
			found = 1;
		}

		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));
	}
	if (rta_parent != rta_child)
		printf("rta pointers are off\n");

	if (found)
		return 0;
	else	return -1;
}

/*
static int set_hw_all(char *ifname)
{
	struct nlmsghdr *nlh;
	int status = 1;

	nlh = start_msg(CMD, DCB_CMD_SET_ALL);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	add_rta(nlh, DCB_ATTR_SET_ALL, (void *)&status, sizeof(__u8));

	return send_msg(nlh);
}*/

static int get_bcn(char *ifname, bcn_cfg *bcn_data)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int i, j;
	unsigned int temp_int;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_BCN_GCFG);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname,
	        strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_BCN, NULL, 0);
	rta_child = add_rta(nlh, DCB_BCN_ATTR_ALL, NULL, 0);
	rta_parent->rta_len += NLMSG_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
	{
		printf("error getting BCN cfg.\n");	
		return -EIO;
	}

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_BCN_GCFG) {
		printf("Hmm, this is not the message we were expecting.\n");
		free(nlh);
		return -EIO;
	}
	if (rta_parent->rta_type != DCB_ATTR_BCN) {
		/* Do we really want to code up an attribute parser?? */
		printf("A full libnetlink (with rtnl and attribute support) "
		       "would sure be nice.\n");
		free(nlh);
		return -EIO;
	}
	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));
	for (i = 0; rta_parent > rta_child; i++) {
		if (i == DCB_BCN_ATTR_RP_ALL - DCB_BCN_ATTR_RP_0) {
			printf("bcn param out of range\n");
			break;
		}
		bcn_data->up_settings[rta_child->rta_type
			- DCB_BCN_ATTR_RP_0].rp_admin = 
				*(__u8 *)NLA_DATA(rta_child);
		rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	}

	for (i = 0; i < BCN_ADDR_OPTION_LEN/4; i++) { /*2 bytes for BCNA data */
		temp_int = *(__u32 *)NLA_DATA(rta_child);
		rta_child = (struct rtattr *)((char *)rta_child +
					     NLMSG_ALIGN(rta_child->rta_len));
		for (j = 0; j < 4; j++) {
			bcn_data->bcna[j+i*4] = 
			    (__u8)((temp_int & (0xFF << (j*8))) >> (j*8));
		}
	}

	memcpy((void *)&bcn_data->rp_alpha, (__u32 *)NLA_DATA(rta_child),
		sizeof(__u32));
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	memcpy((void *)&bcn_data->rp_beta, (__u32 *)NLA_DATA(rta_child),
		sizeof(__u32));
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	memcpy((void *)&bcn_data->rp_gd, (__u32 *)NLA_DATA(rta_child),
		sizeof(__u32));
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	memcpy((void *)&bcn_data->rp_gi, (__u32 *)NLA_DATA(rta_child),
		sizeof(__u32));
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_tmax = *(__u32 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_td = *(__u16 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_rmin = *(__u16 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_w = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_rd = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_ru = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_wrtt = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	bcn_data->rp_ri = *(__u32 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		                              NLMSG_ALIGN(rta_child->rta_len));

	if (rta_parent != rta_child)
		printf("rta pointers are off\n");

	return 0;
}

/* returns: 0 on success
 *          1 on failure
*/
static int set_bcn_cfg(char *ifname, bcn_cfg *bcn_data)
{
	struct nlmsghdr *nlh;
	struct rtattr *rta_parent, *rta_child;

	int i;
	int temp_int;

	printf("set_bcn_cfg: %s\n", ifname);

	nlh = start_msg(RTM_SETDCB, DCB_CMD_BCN_SCFG);
	if (NULL == nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_BCN, NULL, 0);
	for (i = DCB_BCN_ATTR_RP_0; i <= DCB_BCN_ATTR_RP_7; i++) {
		rta_child = add_rta(nlh, i, 
		   (void *)&bcn_data->up_settings[i - DCB_BCN_ATTR_RP_0].rp_admin,
		     sizeof(__u8));
		rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);
	}

	temp_int = 0;
	for (i = 0; i < BCN_ADDR_OPTION_LEN/2; i++)
		temp_int |= bcn_data->bcna[i]<<(i*8);
	rta_child = add_rta(nlh, DCB_BCN_ATTR_BCNA_0, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);	

	temp_int = 0;
	for (i = BCN_ADDR_OPTION_LEN/2; i < BCN_ADDR_OPTION_LEN; i++)
		temp_int |= bcn_data->bcna[i]<<((i- BCN_ADDR_OPTION_LEN/2)*8);
	rta_child = add_rta(nlh, DCB_BCN_ATTR_BCNA_1, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);	

	rta_child = add_rta(nlh, DCB_BCN_ATTR_ALPHA, 
		(void *)&bcn_data->rp_alpha, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_BCN_ATTR_BETA, 
		(void *)&bcn_data->rp_beta, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_BCN_ATTR_GD, 
		(void *)&bcn_data->rp_gd, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_BCN_ATTR_GI, 
		(void *)&bcn_data->rp_gi, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_BCN_ATTR_TMAX, 
		(void *)&bcn_data->rp_tmax, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_td;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_TD, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_rmin;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_RMIN, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_w;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_W, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_rd;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_RD, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_ru;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_RU, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	temp_int = (int)bcn_data->rp_wrtt;
	rta_child = add_rta(nlh, DCB_BCN_ATTR_WRTT, 
		(void *)&temp_int, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_BCN_ATTR_RI, 
		(void *)&bcn_data->rp_ri, sizeof(__u32));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	return(recv_msg(DCB_CMD_BCN_SCFG, DCB_ATTR_BCN));
}

static int set_hw_bcn(char *device_name, bcn_cfg *bcn_data,
	__u8 oper_mode)
{
	int i;
	bcn_cfg                bcn_store;
	bcn_cfg                *bcn_temp;

	oper_mode = 1;

	{
		for (i = 0; i <= 8; i++) {
			bcn_data->up_settings[i].rp_admin = 1;
		}	
		bcn_data->rp_alpha = 0.5;
		bcn_data->rp_beta  = 0.1;
		bcn_data->rp_gd    = 0.00026; /* Based on other default parameters */
		bcn_data->rp_gi    = 0.53; /* Based on other default parameters */
		bcn_data->rp_tmax  = 100;
		bcn_data->rp_td    = 100;
		bcn_data->rp_rmin  = 100;
		bcn_data->rp_w     = 9;
		bcn_data->rp_rd    = 1;
		bcn_data->rp_ru    = 1;
		bcn_data->rp_ri    = 5001;
		bcn_data->rp_wrtt  = 9;
	}	

	if (!oper_mode) /* oper mode is false */
	{
		//get_bcn(DEF_CFG_STORE, &bcn_store);
		bcn_temp = &bcn_store;
	} else {
		bcn_temp = bcn_data;
	}

	for (i = 0; i < 8; i++) {
		if (bcn_temp->up_settings[i].cp_admin)
			bcn_temp->up_settings[i].cp_admin = 1;
		else
			bcn_temp->up_settings[i].cp_admin = 0;
	}
 
	return set_bcn_cfg(device_name, bcn_temp);
}

#ifdef DCB_APP_DRV_IF_SUPPORTED
static int get_app_cfg(char *ifname, appgroup_attribs *app_data)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *rta_parent, *rta_child;
	int rval = 0;
	__u8 idtype;
	__u16 id;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_GAPP);
	if (NULL==nlh)
		return -EIO;

	add_rta(nlh, DCB_ATTR_IFNAME, (void *)ifname, strlen(ifname) + 1);
	rta_parent = add_rta(nlh, DCB_ATTR_APP, NULL, 0);

	rta_child = add_rta(nlh, DCB_APP_ATTR_IDTYPE, 
		(void *)&app_data->dcb_app_idtype, sizeof(__u8));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	rta_child = add_rta(nlh, DCB_APP_ATTR_ID, 
		(void *)&app_data->dcb_app_id, sizeof(__u16));
	rta_parent->rta_len += NLA_ALIGN(rta_child->rta_len);

	if (send_msg(nlh))
		return -EIO;

	nlh = get_msg();
	if (!nlh)
		return -EIO;

	d = (struct dcbmsg *)NLMSG_DATA(nlh);
	rta_parent = (struct rtattr *)(((char *)d) +
		NLMSG_ALIGN(sizeof(struct dcbmsg)));

	if (d->cmd != DCB_CMD_GAPP) {
		printf("Hmm, this is not the message we were expecting.\n");
		rval = -EIO;
		goto get_error;
	} 
	if (rta_parent->rta_type != DCB_ATTR_APP) {
		printf("A full libnetlink (with genl and attribute support) "
		       "would sure be nice.\n");
		rval = -EIO;
		goto get_error;
	}

	rta_child = NLA_DATA(rta_parent);
	rta_parent = (struct rtattr *)((char *)rta_parent +
	                               NLMSG_ALIGN(rta_parent->rta_len));

	idtype = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));
	if (idtype != app_data->dcb_app_idtype) {
		rval = -EIO;
		goto get_error;
	}

	id = *(__u16 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));
	if (id != app_data->dcb_app_id) {
		rval = -EIO;
		goto get_error;
	}

	app_data->dcb_app_priority = *(__u8 *)NLA_DATA(rta_child);
	rta_child = (struct rtattr *)((char *)rta_child +
		             NLMSG_ALIGN(rta_child->rta_len));

	if (rta_parent != rta_child)
		printf("rta pointers are off\n");

get_error:
	free(nlh);
	return rval;
}

int set_hw_app0(char *ifname, appgroup_attribs *app_data)
{
	struct nlmsghdr *nlh;
	struct rtattr *rta_parent, *rta_child;

	printf("set_hw_app0: %s\n", ifname);

	nlh = start_msg(RTM_SETDCB, DCB_CMD_SAPP);
	if (NULL == nlh)
		return -EIO;

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

	return(recv_msg(DCB_CMD_SAPP, DCB_ATTR_APP));
}
#endif /* DCB_APP_DRV_IF_SUPPORTED */

void print_app(struct rtattr *app_attr)
{
	struct dcb_app *data;

	data = RTA_DATA(app_attr);
	printf("selector %i protocol %i priority %i\n",
		data->selector, data->protocol, data->priority);
}

void print_pfc(struct ieee_pfc *pfc)
{
	int i;
	printf("PFC:\n");
	printf("\t cap %2x en %2x\n", pfc->pfc_cap, pfc->pfc_en);
	printf("\t mbc %2x delay %i\n", pfc->mbc, pfc->delay);

	printf("\t requests: ");
	for (i = 0; i < 8; i++)
		printf("%lli ", pfc->requests[i]);
	printf("\n");

	printf("\t requests: ");
	for (i = 0; i < 8; i++)
		printf("%lli ", pfc->indications[i]);
	printf("\n");
}

void print_ets(struct ieee_ets *ets)
{
	int i;
	printf("ETS:\n");
	printf("\tcap %2x cbs %2x\n", ets->ets_cap, ets->cbs);

	printf("\tets tc_tx_bw: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_tx_bw[i]);
	printf("\n");

	printf("\tets tc_rx_bw: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_rx_bw[i]);
	printf("\n");

	printf("\tets tc_tsa: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->tc_tsa[i]);
	printf("\n");

	printf("\tets prio_tc: ");
	for (i = 0; i < 8; i++)
		printf("%i ", ets->prio_tc[i]);
	printf("\n");
}

int set_ieee(char *ifname, struct ieee_ets *ets_data, struct ieee_pfc *pfc_data,
	     struct dcb_app *app_data)
{
	struct nlmsghdr *nlh;
	struct rtattr *ieee, *apptbl;

	nlh = start_msg(RTM_SETDCB, DCB_CMD_IEEE_SET);
	if (NULL == nlh)
		return -EIO;

	addattr_l(nlh, DCB_ATTR_IFNAME, ifname, strlen(ifname) + 1);
	ieee = addattr_nest(nlh, DCB_ATTR_IEEE);
	if (ets_data)
		addattr_l(nlh, DCB_ATTR_IEEE_ETS, ets_data, sizeof(*ets_data));
	if (pfc_data)
		addattr_l(nlh, DCB_ATTR_IEEE_PFC, pfc_data, sizeof(*pfc_data));
	if (app_data) {
		apptbl = addattr_nest(nlh, DCB_ATTR_IEEE_APP_TABLE);
		addattr_l(nlh, DCB_ATTR_IEEE_APP, app_data, sizeof(*app_data));
#if 1
		app_data->protocol++;
		addattr_l(nlh, DCB_ATTR_IEEE_APP, app_data, sizeof(*app_data));
#endif
		addattr_nest_end(nlh, apptbl);
	}
	addattr_nest_end(nlh, ieee);

	if (send_msg(nlh))
		return -EIO;

	return recv_msg(DCB_CMD_IEEE_SET, DCB_ATTR_IEEE);
}

#define DCB_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct dcbmsg))))

int get_ieee(char *ifname)
{
	struct nlmsghdr *nlh;
	struct dcbmsg *d;
	struct rtattr *dcb, *ieee[DCB_ATTR_IEEE_MAX+1];
	struct rtattr *tb[DCB_ATTR_MAX + 1];
	int len;

	nlh = start_msg(RTM_GETDCB, DCB_CMD_IEEE_GET);
	if (NULL == nlh) {
		printf("start_msg failed\n");
		return -EIO;
	}

	addattr_l(nlh, DCB_ATTR_IFNAME, ifname, strlen(ifname) + 1);
	if (send_msg(nlh)) {
		printf("send failure\n");
		return -EIO;
	}

	/* Receive 802.1Qaz parameters */
	memset(nlh, 0, MAX_MSG_SIZE);
	len = recv(nl_sd, (void *)nlh, MAX_MSG_SIZE, 0);
	if (len < 0) {
		perror("ieee_get");
		return -EIO;
	}

	if (nlh->nlmsg_type != RTM_GETDCB) {
		struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(nlh);
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			printf("NLMSG_ERROR: err(%i): %s\n",
				err->error, strerror(err->error * -1));
		}
		return -1;
	}

	d = NLMSG_DATA(nlh);
	len -= NLMSG_LENGTH(sizeof(*d));
	if (len < 0) {
		printf("Broken message\n");
		return -1;
	}

	parse_rtattr(tb, DCB_ATTR_MAX, DCB_RTA(d), len);
	if (!tb[DCB_ATTR_IEEE]) {
		printf("Missing DCB_ATTR_IEEE attribute!\n");
		return -1;
	}

	if (tb[DCB_ATTR_IFNAME]) {
		printf("\tifname %s\n", (char *)RTA_DATA(tb[DCB_ATTR_IFNAME]));
	} else {
		printf("Missing DCB_ATTR_IFNAME attribute!\n");
		return -1;
	}

	dcb = tb[DCB_ATTR_IEEE];
	parse_rtattr_nested(ieee, DCB_ATTR_IEEE_MAX, dcb);
	if (ieee[DCB_ATTR_IEEE_ETS]) {
		struct ieee_ets *ets = RTA_DATA(ieee[DCB_ATTR_IEEE_ETS]);
		print_ets(ets);
	}

	if (ieee[DCB_ATTR_IEEE_PFC]) {
		struct ieee_pfc *pfc = RTA_DATA(ieee[DCB_ATTR_IEEE_PFC]);
		print_pfc(pfc);
	}

	if (ieee[DCB_ATTR_IEEE_APP_TABLE]) {
		struct rtattr *i, *app_list = ieee[DCB_ATTR_IEEE_APP_TABLE];
		int rem = RTA_PAYLOAD(app_list);
		printf("APP:\n");
		for (i = RTA_DATA(app_list);
		     RTA_OK(i, rem);
		     i = RTA_NEXT(i, rem))
			print_app(i);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct tc_config tc[8];
	int i, err = 0;
	int newstate = -1;
	__u8 state;
	__u8 pfc[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	__u8 bwg[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	__u8 mac[ETH_ALEN], san_mac[ETH_ALEN];
	__u8 cap[DCB_CAP_ATTR_MAX+1];
	__u8 numtcs;
	bcn_cfg bcn_set_data, bcn_data;
#ifdef DCB_APP_DRV_IF_SUPPORTED
	appgroup_attribs app_data = {DCB_APP_IDTYPE_ETHTYPE, 0x8906, 0x08};
#endif /* DCB_APP_DRV_IF_SUPPORTED */
	int ifindex;
  
	printf("Calling RTNETLINK interface.\n");
	if (argc < 2) {
		fprintf(stderr, "usage: %s <ifname> [on|off]\n", argv[0]);
		exit(1);
	}

	if (argc >= 3) {
		if (!strcmp(argv[2], "on"))
			newstate = 1;
		if (!strcmp(argv[2], "off"))
			newstate = 0;
	}

	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		printf("no ifindex for %s\n", argv[1]);
		exit(1);
	}

	if ((nl_sd = init_socket()) < 0) {
		fprintf(stderr, "error creating netlink socket\n");
		return nl_sd;
	}

#ifdef DO_GETLINK_QUERY
	printf("DOING A GETLINK COMMAND\n");
	nlh = start_msg(RTM_GETLINK, ifindex);
	if (nlh == NULL)
		exit(1);
	if (send_msg(nlh))
		exit(1);
	free(nlh);
	nlh = get_msg();
#endif

	printf("GETTING DCB STATE\n");
	err = get_state(argv[1], &state);
	if (err) {
		fprintf(stderr, "Error getting DCB state\n");
		goto err_main;
	}
	printf("DCB State = %d\n", state);
	
	if (newstate >= 0) {
		printf("\nSETTING DCB STATE TO: %d\n", newstate);
		err = set_state(argv[1], newstate);
		if (err)
			goto err_main;

		err = get_state(argv[1], &state);
		if (err) {
			fprintf(stderr, "Error getting DCB state\n");
			goto err_main;
		}
		printf("New DCB State = %d\n", state);
	}

	printf("\nGETTING PFC CONFIGURATION\n");
	for (i=0; i<8; i++)
		pfc[i] = 0x0f;
	get_pfc_cfg(argv[1], pfc);
	printf("PFC config:\n");
	for (i=0; i<8; i++)
		printf("%x ", pfc[i]);
	printf("\n");

	get_pfc_state(argv[1], &state);
	if (err) {
		fprintf(stderr, "Error getting PFC status\n");
		goto err_main;
	}
	printf("PFC State = %d\n", state);

	printf("\nGETTING PG TX CONFIGURATION\n");
	get_pg(argv[1], tc, bwg, DCB_CMD_PGTX_GCFG);
	for (i = 0; i < 8; i++) {
		printf("%d: pr=%d\tbwgid=%d\tbw%%=%d\tu2t=%d\tlk%%=%d\n", i,
			tc[i].prio_type,
			tc[i].bwg_id,
			tc[i].bwg_percent,
			tc[i].up_to_tc_bitmap,
			bwg[i]);

		tc[i].prio_type = 3;
		tc[i].bwg_id = i;
		tc[i].bwg_percent = 100;
		tc[i].up_to_tc_bitmap = i;
		bwg[i] = 12 + (i & 1);
	}

	printf("\nGETTING PG RX CONFIGURATION\n");
	memset(bwg, 0, sizeof(bwg));
	memset(&tc[0], 0, sizeof(tc));
	get_pg(argv[1], tc, bwg, DCB_CMD_PGRX_GCFG);
	for (i = 0; i < 8; i++) {
		printf("%d: pr=%d\tbwgid=%d\tbw%%=%d\tu2t=%d\tlk%%=%d\n", i,
			tc[i].prio_type,
			tc[i].bwg_id,
			tc[i].bwg_percent,
			tc[i].up_to_tc_bitmap,
			bwg[i]);
	}

	printf("\nGETTING PERMANENT MAC: ");
	get_perm_hwaddr(argv[1], mac, san_mac);
	for (i = 0; i < 5; i++)
		printf("%02x:", mac[i]);
	printf("%02x\n", mac[i]);

	printf("\nGETTING SAN MAC: ");
	for (i = 0; i < 5; i++)
		printf("%02x:", san_mac[i]);
	printf("%02x\n", san_mac[i]);

	printf("\nGETTING DCB CAPABILITIES\n");
	get_cap(argv[1], &cap[0]);

	printf("\nGET NUMBER OF PG TCS\n");
	if (!get_numtcs(argv[1], DCB_NUMTCS_ATTR_PG, &numtcs))
		printf("num = %d\n", numtcs);
	else	printf("not found\n");

	printf("\nGET NUMBER OF PFC TCS\n");
	if (!get_numtcs(argv[1], DCB_NUMTCS_ATTR_PFC, &numtcs))
		printf("num = %d\n", numtcs);
	else	printf("not found\n");

	printf("\nTEST SET NUMBER OF PG TCS\n");
	if (!set_numtcs(argv[1], DCB_NUMTCS_ATTR_PG, numtcs))
		printf("set passed\n");
	else	printf("error\n");

	printf("\nTEST SET NUMBER OF PFC TCS\n");
	if (!set_numtcs(argv[1], DCB_NUMTCS_ATTR_PFC, numtcs))
		printf("set passed\n");
	else	printf("error\n\n");

/*	printf("set_pfc_cfg = %d\n", set_pfc_cfg(argv[1], pfc)); */
/*	printf("set_rx_pg = %d\n", set_pg(argv[1], tc, bwg, DCB_CMD_PGRX_SCFG));*/
/*	printf("set_hw_all = %d\n", set_hw_all(argv[1])); */

	err = set_hw_bcn(argv[1], &bcn_set_data, 1);
	printf("set_bcn_cfg result is %d.\n", err);

	/*set_hw_all(argv[1]);*/

	get_bcn(argv[1], &bcn_data);
	printf("\nGETTING BCN: \n");
	for (i = 0; i < 8; i++) {
		printf("BCN RP %d: %d\n", i, 
			bcn_data.up_settings[i].rp_admin);
	}
	printf("\nBCN RP ALPHA: %f\n", bcn_data.rp_alpha);
	printf("BCN RP BETA : %f\n", bcn_data.rp_beta);
	printf("BCN RP GD   : %f\n", bcn_data.rp_gd);
	printf("BCN RP GI   : %f\n", bcn_data.rp_gi);
	printf("BCN RP TMAX : %d\n", bcn_data.rp_tmax);
	printf("BCN RP RI   : %d\n", bcn_data.rp_ri);
	printf("BCN RP TD   : %d\n", bcn_data.rp_td);
	printf("BCN RP RMIN : %d\n", bcn_data.rp_rmin);
	printf("BCN RP W    : %d\n", bcn_data.rp_w);
	printf("BCN RP RD   : %d\n", bcn_data.rp_rd);
	printf("BCN RP RU   : %d\n", bcn_data.rp_ru);
	printf("BCN RP WRTT : %d\n", bcn_data.rp_wrtt);

#ifdef DCB_APP_DRV_IF_SUPPORTED
	printf("\nSETTING APP:\n");
	if (set_hw_app0(argv[1], &app_data)) {
		printf("Fail to set app data.\n");
		goto err_main;
	}

	printf("\nGETTING APP:\n");
	if (!get_app_cfg(argv[1], &app_data)) {
		printf("APP ID TYPE: ");
		if (app_data.dcb_app_idtype)
			printf(" \t DCB_APP_IDTYPE_ETHTYPE.\n");
		else
			printf(" \t DCB_APP_IDTYPE_PORTNUM.\n");

		printf(" APP ID: 0x%0x.\n", app_data.dcb_app_id);
		printf(" APP PRIORITY: 0x%0x.\n", app_data.dcb_app_priority);
	}
	else {
		printf("GETTING APP FAILED!.\n"); 
	}
#endif /* DCB_APP_DRV_IF_SUPPORTED */

	if (1) {
		struct ieee_ets ets = {
			.willing = 0, .ets_cap = 0x1, .cbs = 0,
			.tc_tx_bw = {25, 25, 25, 25, 0, 0, 0, 0},
			.tc_rx_bw = {0, 0, 0, 0, 25, 25, 25, 25},
			.tc_tsa = {1, 2, 3, 4, 1, 2, 3, 4},
			.prio_tc = {1, 2, 3, 4, 1, 2, 3, 4}
		};
		struct ieee_pfc pfc = {
			.pfc_cap = 0xf1, .pfc_en = 0, .mbc = 0, .delay = 0x32
		};
		struct dcb_app app = {
			.selector = 0, .priority = 4, .protocol = 0x8906
		};

		printf("\nSETTING ETS:\n");
		set_ieee(argv[1], &ets, &pfc, &app);
	}

	get_ieee(argv[1]);

err_main:
	close(nl_sd);
	return err;
}
