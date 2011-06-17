/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software 
  Copyright(c) 2007-2010 Intel Corporation.

  Substantially modified from:
  hostapd-0.5.7
  Copyright (c) 2002-2007, Jouni Malinen <jkmaline@cc.hut.fi> and
  contributors

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
#include <string.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "lldpad.h"
#include "eloop.h"
#include "ctrl_iface.h"
#include "dcb_protocol.h"
#include "list.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp/ports.h"
#include "lldp_dcbx.h"
#include "lldp_util.h"
#include "messages.h"

extern struct lldp_head lldp_head;

struct ctrl_dst {
	struct ctrl_dst *next;
	struct sockaddr_un addr;
	socklen_t addrlen;
	int debug_level;
	int errors;
	u32 *tlv_types; /*tlv event types to recv */
};

static char *hexlist = "0123456789abcdef";

struct clif_cmds {
	int cmd;
	int (*cmd_handler)(struct clif_data *cd,
			     struct sockaddr_un *from,
			     socklen_t fromlen,
			     char *ibuf, int ilen,
			     char *rbuf);
};	

static const struct clif_cmds cmd_tbl[] = {
	{ DCB_CMD,     clif_iface_module },
	{ MOD_CMD,     clif_iface_module },
	{ ATTACH_CMD,  clif_iface_attach },
	{ DETACH_CMD,  clif_iface_detach },
	{ LEVEL_CMD,   clif_iface_level },
	{ PING_CMD,    clif_iface_ping },
	{ UNKNOWN_CMD, clif_iface_cmd_unknown }
};

/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_module(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen,
				     char *ibuf, int ilen,
				     char *rbuf)
{
	u32 module_id;
	char *cmd_start;
	int cmd_len;
	struct lldp_module *mod = NULL;

	/* identify the module and start of command */
	switch (*ibuf) {
	case DCB_CMD:
		/* Message does not contain a module id, therefore this
		 * message is a DCBX message.  Set module_id to correct value.
		 */
		module_id = 0x001b2101;
		cmd_start = ibuf;
		cmd_len = ilen;
		break;
	case MOD_CMD:
		hexstr2bin(ibuf+MOD_ID, (u8 *)&module_id, sizeof(module_id));
		module_id = ntohl(module_id);
		cmd_start = ibuf + MOD_ID + 2*sizeof(module_id);
		cmd_len = ilen - MOD_ID - 2*sizeof(module_id);
		break;
	default:
		return 1;
	}

	mod = find_module_by_id(&lldp_head, module_id);

	if (mod)
		return  (mod->ops->client_cmd)(clifd, from, fromlen,
			 cmd_start, cmd_len, rbuf+strlen(rbuf));
	else
		return 1;
}


/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_cmd_unknown(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen,
				     char *ibuf, int ilen,
				     char *rbuf)
{
	return 1;
}

/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_ping(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen,
				     char *ibuf, int ilen,
				     char *rbuf)
{
	sprintf(rbuf, "%cPONG", PING_CMD);

	return 0;
}


/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_attach(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen,
				     char *ibuf, int ilen,
				     char *rbuf)
{
	struct ctrl_dst *dst;
	char *tlv, *str, *tokenize;
	const char *delim = ",";
	int i, tlv_count = 0;
	u8 *ptr;

	dst = malloc(sizeof(*dst));
	if (dst == NULL)
		return 1;
	memset(dst, 0, sizeof(*dst));
	memcpy(&dst->addr, from, sizeof(struct sockaddr_un));
	dst->addrlen = fromlen;
	dst->debug_level = MSG_INFO;
	dst->next = clifd->ctrl_dst;
	clifd->ctrl_dst = dst;

	/*
	 * There are two cases here one, the user provided
	 * no string in which case we must send DCBX events
	 * to be compatible with legacy clients. Two the
	 * user sent a comma seperated string of tlv module
	 * ids it expects events from
	 */

	/* set default string to DCBX Events */
	if (ibuf[1] == '\0') {
		u32 hex = LLDP_MOD_DCBX;
		tlv = malloc(sizeof(char) * (8 + 1));
		if (!tlv)
			goto err_tlv;
		tlv[0] = 'A';
		bin2hexstr((u8*)&hex, 4, &tlv[1], 8);
	} else
		tlv = strdup(ibuf);

	str = tlv;
	str++;
	/* Count number of TLV Modules */
	tokenize = strtok(str, delim);
	tlv_count++;
	do {
		tokenize = strtok(NULL, delim);
		tlv_count++;
	} while (tokenize);
			
	dst->tlv_types = malloc(sizeof(u32) * tlv_count);
	if (!dst->tlv_types)
		goto err_types;
	memset(dst->tlv_types, 0, sizeof(u32) * tlv_count);

	/* Populate tlv_types from comma separated string */
	tokenize = strtok(str, delim);
	for (i=0; tokenize; i++) {
		ptr = (u8*)&dst->tlv_types[i];
		hexstr2bin(tokenize, ptr, 4);
		tokenize = strtok(NULL, delim);
	}

	/* Insert Termination Pattern */
	dst->tlv_types[i] = ~0;
	free(tlv);

	LLDPAD_DBG("CTRL_IFACE monitor attached\n");
	sprintf(rbuf, "%c", ATTACH_CMD);

	return 0;
err_types:
	free(tlv);
err_tlv:
	LLDPAD_DBG("CTRL_IFACE monitor attach error\n");
	sprintf(rbuf, "%c", ATTACH_CMD);

	return -1;
}

/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
static int detach_clif_monitor(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen)
{
	struct ctrl_dst *dst, *prev = NULL;

	dst = clifd->ctrl_dst;
	while (dst) {
		if (fromlen == dst->addrlen &&
		    memcmp(from->sun_path, dst->addr.sun_path,
			fromlen-sizeof(from->sun_family)) == 0) {
			if (prev == NULL)
				clifd->ctrl_dst = dst->next;
			else
				prev->next = dst->next;
			free(dst->tlv_types);
			free(dst);
			dst = NULL;
			LLDPAD_DBG("CTRL_IFACE monitor detached\n");

			return 0;
		}
		prev = dst;
		dst = dst->next;
	}
	return 1;
}

/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_detach(struct clif_data *clifd,
				     struct sockaddr_un *from,
				     socklen_t fromlen,
				     char *ibuf, int ilen,
				     char *rbuf)
{
	sprintf(rbuf, "%c", DETACH_CMD);
	return detach_clif_monitor(clifd, from, fromlen);
}


/*
 *	Returns a status value.  0 is successful, 1 is an error.
*/
int clif_iface_level(struct clif_data *clifd,
				    struct sockaddr_un *from,
				    socklen_t fromlen,
				    char *ibuf, int ilen,
				    char *rbuf)
{
	struct ctrl_dst *dst;
	char *level;

	level = ibuf+1;
	sprintf(rbuf, "%c", LEVEL_CMD);

	LLDPAD_DBG("CTRL_IFACE LEVEL %s", level);

	dst = clifd->ctrl_dst;
	while (dst) {
		if (fromlen == dst->addrlen &&
		    memcmp(from->sun_path, dst->addr.sun_path,
			fromlen-sizeof(from->sun_family)) == 0) {
			LLDPAD_DBG("CTRL_IFACE changed monitor level\n");

			return 0;
		}
		dst = dst->next;
	}

	return 1;
}

static int find_cmd_entry(int cmd)
{
	int i;

	for (i = 0; cmd_tbl[i].cmd != cmd && cmd_tbl[i].cmd != UNKNOWN_CMD; i++)
		;

	return (i);
}

static void process_clif_cmd(  struct clif_data *cd,
			struct sockaddr_un *from,
			socklen_t fromlen,
			char *ibuf, int ilen, char *rbuf, int *rlen)
{
	int status;

	/* setup minimum command response message
	 * status will be updated at end */
	sprintf(rbuf, "%c%02x", CMD_RESPONSE, dcb_failed);
	*rlen = strlen(rbuf);

	if (ilen < 1) {
		return;
	}

	status = cmd_tbl[find_cmd_entry((int)ibuf[0])].cmd_handler(
		cd, from, fromlen, ibuf, ilen, rbuf+strlen(rbuf));

	/* update status and compute final length */
	rbuf[CLIF_STAT_OFF] = hexlist[ (status & 0x0f0) >> 4 ];
	rbuf[CLIF_STAT_OFF+1] = hexlist[ status & 0x0f ];
	*rlen = strlen(rbuf);
}


static void ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct clif_data *clifd = eloop_ctx;
	char buf[MAX_CLIF_MSGBUF];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = MAX_CLIF_MSGBUF;
	int reply_len;

	res = recvfrom(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT,
		       (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';

	reply = malloc(reply_size);
	if (reply == NULL) {
		sendto(sock, "FAIL", 4, 0, (struct sockaddr *) &from,
		       fromlen);
		return;
	}

	memset(reply, 0, reply_size);
	process_clif_cmd(clifd, &from, fromlen, buf, res, reply, &reply_len);

	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	free(reply);
}


static char *ctrl_iface_path(struct clif_data *clifd)
{
	char *buf;
	size_t len;

	if (clifd->ctrl_interface == NULL)
		return NULL;

	len = strlen(clifd->ctrl_interface) + strlen(clifd->iface) +
		2;
	buf = malloc(len);
	if (buf == NULL)
		return NULL;

	snprintf(buf, len, "%s/%s",
		 clifd->ctrl_interface, clifd->iface);
	buf[len - 1] = '\0';
	return buf;
}


int ctrl_iface_register(struct clif_data *clifd)
{
	return eloop_register_read_sock(clifd->ctrl_sock, ctrl_iface_receive,
					clifd, NULL);
}

int ctrl_iface_init(struct clif_data *clifd)
{
	struct sockaddr_un addr;
	int s = -1;
	char *fname = NULL;
	int retry;

	clifd->ctrl_sock = -1;
	clifd->ctrl_dst = NULL;

	if (clifd->ctrl_interface == NULL)
		return 0;

	if (mkdir(clifd->ctrl_interface, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			LLDPAD_DBG("Using existing control "
				   "interface directory.");
		} else {
			perror("mkdir[ctrl_interface]");
			goto fail;
		}
	}

	if (clifd->ctrl_interface_gid_set &&
	    chown(clifd->ctrl_interface, 0,
		  clifd->ctrl_interface_gid) < 0) {
		perror("chown[ctrl_interface]");
		return -1;
	}

	if (strlen(clifd->ctrl_interface) + 1 + strlen(clifd->iface)
	    >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	fname = ctrl_iface_path(clifd);
	if (fname == NULL)
		goto fail;

	strncpy(addr.sun_path, fname, sizeof(addr.sun_path));
	for (retry = 0; retry < 2; retry++) {
		if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			if (errno == EADDRINUSE) {
				unlink(fname);
			}
		}
		else {
			break;
		}
	}
	if (retry == 2) {
		perror("bind(PF_UNIX)");
		goto fail;
	}

	if (clifd->ctrl_interface_gid_set &&
	    chown(fname, 0, clifd->ctrl_interface_gid) < 0) {
		perror("chown[ctrl_interface/ifname]");
		goto fail;
	}

	if (chmod(fname, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	free(fname);

	clifd->ctrl_sock = s;

	return 0;

fail:
	if (s >= 0)
		close(s);
	if (fname) {
		unlink(fname);
		free(fname);
	}
	return -1;
}


void ctrl_iface_deinit(struct clif_data *clifd)
{
	struct ctrl_dst *dst, *prev;

	if (clifd->ctrl_sock > -1) {
		eloop_unregister_read_sock(clifd->ctrl_sock);
		close(clifd->ctrl_sock);
		clifd->ctrl_sock = -1;

		if (clifd->ctrl_interface &&
		    rmdir(clifd->ctrl_interface) < 0) {
			if (errno == ENOTEMPTY) {
				LLDPAD_DBG("Control interface "
					   "directory not empty - leaving it "
					   "behind");
			} else {
				perror("rmdir[ctrl_interface]");
			}
		}
	}

	dst = clifd->ctrl_dst;
	while (dst) {
		prev = dst;
		dst = dst->next;
		free(prev);
	}

	free(clifd);
}

int is_ctrl_listening(struct ctrl_dst *dst, u32 type)
{
	int i;
	u32 term = ~0;
	u32 all = 0;
	u32 dcbx = LLDP_MOD_DCBX;
	
	if (!dst)
		return 0;

	for (i=0; dst->tlv_types[i] != term; i++) {
		if ((!type && dst->tlv_types[i] == dcbx) ||
		    dst->tlv_types[i] == type || dst->tlv_types[i] == all)
			return 1;
	}

	return 0;
}

void ctrl_iface_send(struct clif_data *clifd, int level, u32 moduleid,
			char *buf, size_t len)
{
	struct ctrl_dst *dst, *next;
	struct msghdr msg;
	int idx, send;
	struct iovec io[3];
	char levelstr[10] = "";
	char modulestr[10] = "";

	dst = clifd->ctrl_dst;
	if (clifd->ctrl_sock < 0 || dst == NULL)
		return;

	snprintf(levelstr, sizeof(levelstr), "%c%d", EVENT_MSG, level);
	if (moduleid) {
		snprintf(modulestr, sizeof(modulestr), "M%08x",moduleid);
		io[0].iov_base = modulestr;
		io[0].iov_len = strlen(modulestr);
	} else {
		io[0].iov_base = NULL;
		io[0].iov_len = 0;
	}
	io[1].iov_base = levelstr;
	io[1].iov_len = strlen(levelstr);
	io[2].iov_base = buf;
	io[2].iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = io;
	msg.msg_iovlen = 3;

	idx = 0;
	while (dst) {
		next = dst->next;
		send = 0;
		/* Does dst receive these event messages? */
		send = is_ctrl_listening(dst, moduleid); 

		/* Yes */
		if (send && level >= dst->debug_level) {
			msg.msg_name = &dst->addr;
			msg.msg_namelen = dst->addrlen;
			if (sendmsg(clifd->ctrl_sock, &msg, 0) < 0) {
				fprintf(stderr,
					"CTRL_IFACE monitor[%d][%d] %d:%s: ",
					idx, clifd->ctrl_sock, dst->addrlen,
					dst->addr.sun_path);
				perror("sendmsg");
				dst->errors++;
				if (dst->errors > 10) {
					detach_clif_monitor(
						clifd, &dst->addr,
						dst->addrlen);
				}
			} else {
				dst->errors = 0;
			}
		}
		idx++;
		dst = next;
	}
}
