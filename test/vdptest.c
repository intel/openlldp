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
 *   - the switch de-associates the VSI profile (switch data base cleaned)
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netlink/msg.h>

#include "clif.h"
#include "clif_msgs.h"

#define	UUIDLEN			16
#define	DIM(x)			(sizeof(x)/sizeof(x[0]))
#define	COPY_OP			"new="
#define	KEYLEN			16
#define CMD_ASSOC	'a'	/* Association */
#define CMD_DEASSOC	'd'	/* DE-Association */
#define CMD_PREASSOC	'p'	/* pre-Association */
#define CMD_RRPREASSOC	'r'	/* pre-Association with RR */
#define CMD_SLEEP	's'	/* Wait some time */
#define CMD_GETMSG	'g'	/* Receive messages */
#define CMD_ECHO	'e'	/* ECHO command */
#define CMD_EXTERN	'E'	/* External command */
#define CMD_SETDF	'X'	/* Change defaults */

/*
 * Set the define MYDEBUG to any value for detailed debugging
 */

enum {
	f_map,
	f_mgrid,
	f_typeid,
	f_typeidver,
	f_uuid
};

struct macvlan {
	unsigned char mac[ETH_ALEN];	/* MAC address */
	unsigned short vlanid;	/* VLAN Id */
};

static struct vdpdata {
	char key[KEYLEN];	/* Profile name */
	unsigned char modified;	/* Field altered */
	unsigned char pairs;	/* # of MAC/VLAN pairs */
	unsigned char mgrid;	/* Manager ID */
	unsigned char typeidver;	/* Type ID version */
	unsigned int typeid;	/* Type ID */
	unsigned char uuid[UUIDLEN];	/* Instance ID */
	struct macvlan addr[10];	/* Pairs of MAC/VLAN */
} vsidata[32];

static struct command {		/* Command structure */
	char key[KEYLEN];	/* Name of profile to use */
	unsigned int waittime;	/* Time (in secs) to wait after cmd */
	unsigned int repeats;	/* # of times to repeat this command */
	unsigned int delay;	/* Delay (in us) before a GETLINK msg */
	unsigned char cmd;	/* Type of command */
	unsigned char no_err;	/* # of expected errors */
	int errors[4];		/* Expected errors */
	int rc;			/* Encountered error */
	char *text;		/* Text to display */
} cmds[32], defaults = {	/* Default values in structure */
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
static char mybuf[1024];	/* Buffer for netlink message decode */

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
	[IFLA_PORT_RESPONSE] = {
		.type = NLA_U16
	}
};

static void uuid2buf(const unsigned char *p, char *buf)
{
	sprintf(buf, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

static int addit(char *format, ...)
{
	size_t left = strlen(mybuf);
	int c;
	va_list ap;

	va_start(ap, format);
	c = vsnprintf(mybuf + left, sizeof mybuf - left, format, ap);
	va_end(ap);
	return (c < 0 || ((unsigned)c >= sizeof mybuf - left)) ? -1 : 0;
}

static int showerror(struct nlmsghdr *nlh)
{
	struct nlmsgerr *err = NLMSG_DATA(nlh);

	if (verbose)
		printf("%s setlink response:%d\n", progname, err->error);
	return err->error;
}

static void parse_vfinfolist(struct nlattr *vfinfolist)
{
	struct nlattr *le1, *vf[IFLA_VF_MAX + 1];
	int rem;

	addit("\tfound IFLA_VFINFO_LIST!\n");
	nla_for_each_nested(le1, vfinfolist, rem) {
		if (nla_type(le1) != IFLA_VF_INFO) {
			fprintf(stderr, "%s nested parsing of"
			    "IFLA_VFINFO_LIST failed\n", progname);
			return;
		}
		if (nla_parse_nested(vf, IFLA_VF_MAX, le1, ifla_vf_policy)) {
			fprintf(stderr, "%s nested parsing of "
			    "IFLA_VF_INFO failed\n", progname);
			return;
		}

		if (vf[IFLA_VF_MAC]) {
			struct ifla_vf_mac *mac = RTA_DATA(vf[IFLA_VF_MAC]);
			unsigned char *m = mac->mac;

			addit("\tIFLA_VF_MAC=%02x:%02x:%02x:"
			    " %02x:%02x:%02x\n",
			    m[0], m[1], m[2], m[3], m[4], m[5]);
		}

		if (vf[IFLA_VF_VLAN]) {
			struct ifla_vf_vlan *vlan = RTA_DATA(vf[IFLA_VF_VLAN]);

			addit("\tIFLA_VF_VLAN=%d\n", vlan->vlan);
		}
	}
}

static void show_nlas(struct nlattr **tb, int max)
{
	int rem;

	for (rem = 0; rem < max; ++rem) {
		if (tb[rem])
			printf("nlattr %02d type:%d len:%d\n", rem,
			    tb[rem]->nla_type, tb[rem]->nla_len);
	}
}

static void showmsg(struct nlmsghdr *nlh, int *status)
{
	struct nlattr *tb[IFLA_MAX + 1], *tb3[IFLA_PORT_MAX + 1];
	struct ifinfomsg ifinfo;
	char *ifname;
	int rem;

	if (status)
		*status = -1;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		if (status)
			*status = showerror(nlh);
		return;
	}
	memset(mybuf, 0, sizeof mybuf);
	addit("\tnlh.nl_pid:%d nlh_type:%d nlh_seq:%#x nlh_len:%#x\n",
	    nlh->nlmsg_pid, nlh->nlmsg_type, nlh->nlmsg_seq, nlh->nlmsg_len);
	memcpy(&ifinfo, NLMSG_DATA(nlh), sizeof ifinfo);
	addit("\tifinfo.family:%#x type:%#x index:%d flags:%#x change:%#x\n",
	    ifinfo.ifi_family, ifinfo.ifi_type, ifinfo.ifi_index,
	    ifinfo.ifi_flags, ifinfo.ifi_change);
	if (nlmsg_parse(nlh, sizeof ifinfo,
		(struct nlattr **)&tb, IFLA_MAX, NULL)) {
		fprintf(stderr, "%s error parsing request...\n", progname);
		return;
	}
	if (verbose >= 3)
		show_nlas(tb, IFLA_MAX);
	if (tb[IFLA_IFNAME]) {
		ifname = (char *)RTA_DATA(tb[IFLA_IFNAME]);
		addit("\tIFLA_IFNAME=%s\n", ifname);
	}
	if (tb[IFLA_OPERSTATE]) {
		rem = *(unsigned short *)RTA_DATA(tb[IFLA_OPERSTATE]);
		addit("\tIFLA_OPERSTATE=%d\n", rem);
	}
	if (tb[IFLA_VFINFO_LIST])
		parse_vfinfolist(tb[IFLA_VFINFO_LIST]);
	if (tb[IFLA_VF_PORTS]) {
		struct nlattr *tb_vf_ports;

		addit("\tfound IFLA_VF_PORTS\n");
		nla_for_each_nested(tb_vf_ports, tb[IFLA_VF_PORTS], rem) {

			if (nla_type(tb_vf_ports) != IFLA_VF_PORT) {
				fprintf(stderr, "%s not a IFLA_VF_PORT, "
				    " skipping\n", progname);
				continue;
			}
			if (nla_parse_nested(tb3, IFLA_PORT_MAX, tb_vf_ports,
				ifla_port_policy)) {
				fprintf(stderr, "%s nested parsing on level 2"
				    " failed\n", progname);
			}
			if (tb3[IFLA_PORT_VF])
				addit("\tIFLA_PORT_VF=%d\n",
				    *(uint32_t *) RTA_DATA(tb3[IFLA_PORT_VF]));
			if (tb3[IFLA_PORT_VSI_TYPE]) {
				struct ifla_port_vsi *pvsi;
				int tid = 0;

				pvsi = (struct ifla_port_vsi *)
				    RTA_DATA(tb3[IFLA_PORT_VSI_TYPE]);
				tid = pvsi->vsi_type_id[2] << 16 |
				    pvsi->vsi_type_id[1] << 8 |
				    pvsi->vsi_type_id[0];
				addit("\tIFLA_PORT_VSI_TYPE=mgr_id:%d "
				    " type_id:%d typeid_version:%d\n",
				    pvsi->vsi_mgr_id, tid,
				    pvsi->vsi_type_version);
			}
			if (tb3[IFLA_PORT_INSTANCE_UUID]) {
				char uuidbuf[64];
				unsigned char *uuid;

				uuid = (unsigned char *)
				    RTA_DATA(tb3[IFLA_PORT_INSTANCE_UUID]);
				uuid2buf(uuid, uuidbuf);
				addit("\tIFLA_PORT_INSTANCE_UUID=%s\n",
				    uuidbuf);
			}
			if (tb3[IFLA_PORT_REQUEST])
				addit("\tIFLA_PORT_REQUEST=%d\n", *(uint8_t *)
				    RTA_DATA(tb3[IFLA_PORT_REQUEST]));
			if (tb3[IFLA_PORT_RESPONSE]) {
				addit("\tIFLA_PORT_RESPONSE=%d\n", *(uint16_t *)
				    RTA_DATA(tb3[IFLA_PORT_RESPONSE]));
				*status = *(int *)
				    RTA_DATA(tb3[IFLA_PORT_RESPONSE]);
			}
		}
	}
	if (verbose >= 2)
		printf("%s", mybuf);
}

/*
 * Wait for a message from LLDPAD
 *
 * Return number of bytes received. 0 means timeout and -1 on error.
 */
static int waitmsg(struct command *cp, int *status)
{
	struct msghdr msg;
	struct sockaddr_nl dest_addr;
	struct iovec iov;
	unsigned char msgbuf[1024];
	struct nlmsghdr *nlh = (struct nlmsghdr *)msgbuf;
	int n, result = 0;
	fd_set readfds;

	struct timeval tv = {
		.tv_sec = cp->waittime
	};

	memset(&msgbuf, 0, sizeof msgbuf);
	memset(&dest_addr, 0, sizeof dest_addr);
	iov.iov_base = (void *)nlh;
	iov.iov_len = sizeof msgbuf;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (verbose)
		printf("%s Waiting %d seconds for message...\n", progname,
		    cp->waittime);
	FD_ZERO(&readfds);
	FD_SET(my_sock, &readfds);
	n = select(my_sock + 1, &readfds, NULL, NULL, &tv);
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
	result = recvmsg(my_sock, &msg, MSG_DONTWAIT);
	if (result < 0)
		fprintf(stderr, "%s receive error:%s\n",
		    progname, strerror(errno));
	else {
		if (verbose)
			printf("%s received %d bytes from %d\n",
			    progname, result, dest_addr.nl_pid);
		showmsg(nlh, status);
	}
	return result;
}

static int lldp_wait(struct command *cp)
{
	int rc = 0;
	unsigned int cnt;

	for (cnt = 0; cnt < cp->repeats && rc >= 0; ++cnt)
		if ((rc = waitmsg(cp, 0))) {
			cp->rc = 1;
			break;
		}
	return rc;
}

/*
 * Construct the GETLINK message to lldpad.
 */
static int mk_nlas(char *buf)
{
	int total;
	struct nlattr *nlap;
	char *cp;
	struct ifinfomsg *to = (struct ifinfomsg *)buf;

	to->ifi_index = ifindex;
	to->ifi_family = AF_UNSPEC;
	total = NLMSG_ALIGN(sizeof *to);
	nlap = (struct nlattr *)(buf + NLMSG_ALIGN(sizeof *to));
	nlap->nla_type = IFLA_IFNAME;
	nlap->nla_len = NLA_HDRLEN + NLA_ALIGN(1 + strlen(ifname));
	total += nlap->nla_len;
	cp = (char *)nlap + NLA_HDRLEN;
	strcpy(cp, ifname);
	return total;
}

/*
 * Send a GETLINK message to lldpad to query the status of the operation.
 */
static int getlink(void)
{
	struct sockaddr_nl d_nladdr;
	struct msghdr msg;
	char buffer[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	struct iovec iov;
	int rc;

	memset(buffer, 0, sizeof buffer);
	/* Destination address */
	memset(&d_nladdr, 0, sizeof d_nladdr);
	d_nladdr.nl_family = PF_NETLINK;
	d_nladdr.nl_pid = lldpad;

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_HDRLEN + mk_nlas((char *)NLMSG_DATA(nlh));
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = RTM_GETLINK;

	/* Iov structure */
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	/* Msg */
	memset(&msg, 0, sizeof msg);
	msg.msg_name = (void *)&d_nladdr;
	msg.msg_namelen = sizeof d_nladdr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if ((rc = sendmsg(my_sock, &msg, 0)) == -1)
		perror(progname);
	if (verbose)
		printf("%s query status --> rc:%d\n", progname, rc);
	return rc;
}

/*
 * Send a RTM_GETLINK message and retrieve the status of the pending
 * command.
 */
static int lldp_ack(struct command *cp)
{
	int bytes;
	int status;

	bytes = getlink();
	if (bytes <= 0)
		return bytes;
	bytes = waitmsg(cp, &status);
	if (bytes <= 0)
		return bytes;
	cp->rc = status;
	if (verbose)
		printf("%s lldp_ack status:%d\n", progname, cp->rc);
	return bytes;
}

static int addvfs(struct nl_msg *nl_msg, struct vdpdata *vdp, unsigned char cmd)
{
	struct nlattr *vfports, *vfport;
	struct ifla_port_vsi vsi;
	unsigned char op;

	switch (cmd) {
	case CMD_ASSOC:
		op = PORT_REQUEST_ASSOCIATE;
		break;
	case CMD_DEASSOC:
		op = PORT_REQUEST_DISASSOCIATE;
		break;
	case CMD_PREASSOC:
		op = PORT_REQUEST_PREASSOCIATE;
		break;
	case CMD_RRPREASSOC:
		op = PORT_REQUEST_PREASSOCIATE_RR;
		break;
	}

	vsi.vsi_mgr_id = vdp->mgrid;
	vsi.vsi_type_version = vdp->typeidver;
	vsi.vsi_type_id[2] = vdp->typeid >> 16;
	vsi.vsi_type_id[1] = vdp->typeid >> 8;
	vsi.vsi_type_id[0] = vdp->typeid;

	if (!(vfports = nla_nest_start(nl_msg, IFLA_VF_PORTS)))
		return -ENOMEM;
	if (!(vfport = nla_nest_start(nl_msg, IFLA_VF_PORT)))
		return -ENOMEM;
	if (nla_put(nl_msg, IFLA_PORT_VSI_TYPE, sizeof vsi, &vsi) < 0)
		return -ENOMEM;
	if (nla_put(nl_msg, IFLA_PORT_INSTANCE_UUID, UUIDLEN, vdp->uuid) < 0)
		return -ENOMEM;
	if (nla_put(nl_msg, IFLA_PORT_REQUEST, sizeof op, &op) < 0)
		return -ENOMEM;
	nla_nest_end(nl_msg, vfport);
	nla_nest_end(nl_msg, vfports);
	return 0;
}

static int addmacs(struct nl_msg *nl_msg, struct vdpdata *vdp)
{
	int i;
	struct nlattr *vfinfolist, *vfinfo;

	if (vdp->pairs == 0)
		return 0;
	if (!(vfinfolist = nla_nest_start(nl_msg, IFLA_VFINFO_LIST)))
		return -ENOMEM;
	for (i = 0; i < vdp->pairs; ++i) {
		if (!(vfinfo = nla_nest_start(nl_msg, IFLA_VF_INFO)))
			return -ENOMEM;

		if (vdp->addr[i].mac) {
			struct ifla_vf_mac ifla_vf_mac;

			ifla_vf_mac.vf = PORT_SELF_VF;
			memcpy(ifla_vf_mac.mac, vdp->addr[i].mac, ETH_ALEN);
			if (nla_put(nl_msg, IFLA_VF_MAC, sizeof ifla_vf_mac,
				&ifla_vf_mac) < 0)
				return -ENOMEM;
		}

		if (vdp->addr[i].vlanid) {
			struct ifla_vf_vlan ifla_vf_vlan = {
				.vf = PORT_SELF_VF,
				.vlan = vdp->addr[i].vlanid,
				.qos = 0,
			};

			if (nla_put(nl_msg, IFLA_VF_VLAN, sizeof ifla_vf_vlan,
				&ifla_vf_vlan) < 0)
				return -ENOMEM;
		}
		nla_nest_end(nl_msg, vfinfo);
	}
	nla_nest_end(nl_msg, vfinfolist);
	return 0;
}

/*
 * Build the netlink message, return total length of message
 */
static int buildmsg(unsigned char *buf, size_t len, unsigned char cmd,
    struct vdpdata *vdp)
{
	struct nlmsghdr *nlh;
	struct nl_msg *nl_msg;
	struct ifinfomsg ifinfo;

	nl_msg = nlmsg_alloc();
	if (!nl_msg)
		goto err_exit;
	ifinfo.ifi_index = ifindex;
	ifinfo.ifi_family = AF_UNSPEC;
	if (nlmsg_append(nl_msg, &ifinfo, sizeof ifinfo, NLMSG_ALIGNTO) < 0)
		goto err_exit;
	if (addmacs(nl_msg, vdp))
		goto err_exit;
	if (addvfs(nl_msg, vdp, cmd))
		goto err_exit;
	/*
	 * Fill the netlink message header
	 */
	nlh = nlmsg_hdr(nl_msg);
	nlh->nlmsg_type = RTM_SETLINK;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = NLM_F_REQUEST;
	if (len < nlh->nlmsg_len)
		goto err_exit;
	memcpy(buf, nlh, nlh->nlmsg_len);
	nlmsg_free(nl_msg);
	return 0;

err_exit:
	if (nl_msg)
		nlmsg_free(nl_msg);
	fprintf(stderr, "%s: can not build netlink message\n", progname);
	return -ENOMEM;
}

/*
 * Send a netlink message to lldpad. Its a SETLINK message to trigger an
 * action. LLDPAD responds with an error netlink message indicating if the
 * profile was accepted.
 * LLDPAD sends negative numbers as error indicators.
 */
static int lldp_send(struct command *cp, struct vdpdata *vdp)
{
	unsigned char sndbuf[1024];
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_nl d_nladdr;
	struct nlmsghdr *nlh = (struct nlmsghdr *)sndbuf;
	int rc, vsiok = 0;

	memset(&d_nladdr, 0, sizeof d_nladdr);
	d_nladdr.nl_family = AF_NETLINK;
	d_nladdr.nl_pid = lldpad;	/* Target PID */

	memset(sndbuf, 0, sizeof sndbuf);
	rc = buildmsg(sndbuf, sizeof sndbuf, cp->cmd, vdp);
	if (rc)
		return -ENOMEM;
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	/* Msg */
	memset(&msg, 0, sizeof msg);
	msg.msg_name = (void *)&d_nladdr;
	msg.msg_namelen = sizeof d_nladdr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	rc = sendmsg(my_sock, &msg, 0);
	if (rc < 0)
		perror(progname);
	else {
		if (verbose)
			printf("%s send message to %d --> rc:%d\n", progname,
			    lldpad, rc);
		rc = waitmsg(cp, &vsiok);
		if (rc > 0)
			rc = vsiok;
		else if (rc == 0)	/* Time out */
			rc = -1;
	}
	return rc;
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
	unsigned long no = strtoul(word, &endp, 0);

	if (word == 0 || *word == '\0') {
		fprintf(stderr, "key %s has missing number\n", key);
		*ec = 1;
		return 0;
	}
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
	char *delim = strchr(value, '-');
	unsigned long vlan;
	int i, ec, x[ETH_ALEN];

	if (!delim) {
		fprintf(stderr, "%s invalid map format %s\n", progname, value);
		return -1;
	}
	vlan = getnumber("map", value, '-', &ec);
	if (ec) {
		fprintf(stderr, "%s invalid vlanid %s\n", progname, value);
		return -1;
	}
	if (vlan >= 4095) {
		fprintf(stderr, "%s vlanid %ld too high\n", progname, vlan);
		return -1;
	}
	++delim;
	ec = sscanf(delim, "%02x:%02x:%02x:%02x:%02x:%02x", &x[0], &x[1],
	    &x[2], &x[3], &x[4], &x[5]);
	if (ec != ETH_ALEN) {
		fprintf(stderr, "%s mac %s invalid\n", progname, delim);
		return -1;
	}
	/* Check for last character */
	delim = strrchr(value, ':') + 2;
	if (*delim && (strchr("0123456789abcdefABCDEF", *delim) == 0
		|| *(delim + 1) != '\0')) {
		fprintf(stderr, "%s last mac part %s invalid\n", progname,
		    delim);
		return -1;
	}
#ifdef MYDEBUG
	for (i = 0; i < ETH_ALEN; ++i)
		printf("x[%d]=%#x ", i, x[i]);
	puts("");

#endif
	for (ec = 0; ec < profile->pairs; ++ec) {
		for (i = 0; i < ETH_ALEN; ++i)
			if (profile->addr[ec].mac[i] != x[i])
				break;
		if (i == ETH_ALEN) {
			fprintf(stderr, "%s duplicate mac address %s\n",
			    progname, value);
			return -1;
		}
	}
	ec = profile->pairs++;
	profile->addr[ec].vlanid = vlan;
	for (i = 0; i < ETH_ALEN; ++i)
		profile->addr[ec].mac[i] = x[i];
	profile->modified |= 1 << f_map;
	return 0;
}

static int check_uuid(char *value, struct vdpdata *profile)
{
	unsigned int rc;
	unsigned int p[UUIDLEN];

	rc = sscanf(value, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		&p[0], &p[1], &p[2], &p[3], &p[4], &p[5], &p[6], &p[7],
		&p[8], &p[9], &p[10], &p[11], &p[12], &p[13], &p[14], &p[15]);
#ifdef MYDEBUG
	int i;

	printf("cc=%d\n", rc);
	for (i = 0; i < UUIDLEN; ++i)
		printf("p[%d]=%#x ", i, p[i]);
	puts("");
#endif
	if (rc != UUIDLEN) {
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
		printf("%s:typeid:%d ec:%d\n", __func__, profile->mgrid, ec);
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
		printf("%s:typeidver:%d ec:%d\n", __func__, profile->mgrid, ec);
#endif
	}
	return ec;
}

static int check_mgrid(char *value, struct vdpdata *profile)
{
	unsigned long no;
	int ec;

	no = getnumber("mgrid", value, '\0', &ec);
	if (!ec) {
		if (no <= 255) {
			profile->mgrid = no;
			profile->modified |= 1 << f_mgrid;
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
	"name"
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
	char buf[32];

	for (i = 0; i < found->pairs; ++i) {
		unsigned char *xp = found->addr[i].mac;

		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		    xp[0], xp[1], xp[2], xp[3], xp[4], xp[5]);
		printf("\t%hd %s\n", found->addr[i].vlanid, buf);
	}
}

static void print_profile(struct vdpdata *found)
{
	char uuid[64];

	printf("key:%s mgrid:%d typeid:%#x typeidver:%d\n",
	    found->key, found->mgrid, found->typeid, found->typeidver);
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
		change->pairs = alter->pairs;
		memcpy(change->addr, alter->addr, sizeof alter->addr);
	}
	if ((alter->modified & (1 << f_mgrid)))
		change->mgrid = alter->mgrid;
	if ((alter->modified & (1 << f_typeid)))
		change->typeid = alter->typeid;
	if ((alter->modified & (1 << f_typeidver)))
		change->typeidver = alter->typeidver;
	if ((alter->modified & (1 << f_uuid)))
		memcpy(change->uuid, alter->uuid, sizeof change->uuid);
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
 * key=###,mgrid=###,typeid=###,typeidver=###,uuid=###,mac=xxx,vlan=xxx{1,10}
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
}

static void isvalid_profile(struct vdpdata *vdp)
{
	char buf[64];
	unsigned char mode = 1 << f_map | 1 << f_mgrid |
	    1 << f_typeid | 1 << f_typeidver | 1 << f_uuid;

	if (vdp->modified != mode) {
		find_field(vdp->modified, buf);
		fprintf(stderr, "%s key %s misses profile fields %s\n",
		    progname, vdp->key, buf);
		memset(vdp->key, 0, sizeof vdp->key);
	}
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
		if (!(vdp = nextfree())) {
			fprintf(stderr, "%s too many profiles\n", progname);
			return -1;
		}
		*vdp = *found;
		strncpy(vdp->key, newkey, sizeof vdp->key);
		change_profile(vdp, &nextone);
	}
	isvalid_profile(vdp);
	return 0;
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
	newkey = profile + 4;
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

static int rc_ok(struct command *cmdp)
{
	int i;

	for (i = 0; i < cmdp->no_err; ++i)
		if (cmdp->rc == cmdp->errors[i])
			return 1;
	return 0;
}

static void cmd_profile(struct command *cmdp)
{
	struct vdpdata *vdp = findkey(cmdp->key);
	int got_ack = 0;
	unsigned int i;

	if (!vdp) {
		cmdp->rc = ENFILE;
		return;
	}
	if ((cmdp->rc = lldp_send(cmdp, vdp)) >= 0)
		for (i = 0; got_ack == 0 && i < cmdp->repeats; ++i) {
			usleep(cmdp->delay * 1000);
			got_ack = lldp_ack(cmdp);
			if (got_ack < 0) {	/* Error */
				cmdp->rc = -1;
				break;
			} else if (got_ack > 0) {	/* Got ack */
				if (rc_ok(cmdp))
					break;
				else
					got_ack = 0;
			}
		}
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
			lldp_wait(&cmds[i]);
			break;
		}
		rc = cmd_checkrc(&cmds[i]);
		if (rc)
			break;
	}
	return rc;
}

#include <net/if.h>

int main(int argc, char **argv)
{
	extern int optind, opterr;
	extern char *optarg;
	int ch, rc, needif = 0;
	char *slash, mybuf[32];

	progname = (slash = strrchr(argv[0], '/')) ? slash + 1 : argv[0];
	while ((ch = getopt(argc, argv, ":A:C:D:F:S::a:d:e:E:g:p:r:s::i:v"))
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
				optarg = mybuf,
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
	if (!needif)
		exit(0);
	if (!ifname) {
		fprintf(stderr, "%s interface missing or nonexistant\n",
		    progname);
		exit(2);
	}
	lldpad_pid();
	if ((my_sock = open_socket(NETLINK_ROUTE)) < 0)
		exit(4);
	if (verbose >= 2)
		show_commands(0);
	rc = runcmds();
	close(my_sock);
	if (verbose >= 2)
		show_commands(1);
	return rc;
}
