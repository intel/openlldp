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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "clif.h"
#include "clif_msgs.h"

#if defined(CONFIG_CLIF_IFACE_UNIX) || defined(CONFIG_CLIF_IFACE_UDP)
#define CLIF_IFACE_SOCKET
#endif /* CONFIG_CLIF_IFACE_UNIX || CONFIG_CLIF_IFACE_UDP */


struct clif  *clif_open()
{
	struct clif *clif;
	socklen_t addrlen;

	clif = malloc(sizeof(*clif));
	if (clif == NULL)
		return NULL;
	memset(clif, 0, sizeof(*clif));

	clif->s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (clif->s < 0) {
		perror("socket");
		free(clif);
		return NULL;
	}

	clif->local.sun_family = AF_LOCAL;
	clif->local.sun_path[0] = '\0';
	snprintf(&clif->local.sun_path[1], sizeof(clif->local.sun_path) - 1,
		    "%s/%d", LLDP_CLIF_SOCK, getpid());
	addrlen = sizeof(sa_family_t) + strlen(clif->local.sun_path + 1) + 1;
	if (bind(clif->s, (struct sockaddr *) &clif->local, addrlen) < 0) {
		perror("bind");
		close(clif->s);
		free(clif);
		return NULL;
	}

	clif->dest.sun_family = AF_LOCAL;
	clif->dest.sun_path[0] = '\0';
	snprintf(&clif->dest.sun_path[1], sizeof(clif->dest.sun_path) - 1,
		    "%s", LLDP_CLIF_SOCK);
	addrlen = sizeof(sa_family_t) + strlen(clif->dest.sun_path + 1) + 1;

	if (connect(clif->s, (struct sockaddr *) &clif->dest, addrlen) < 0) {
		perror("connect");
		close(clif->s);
		free(clif);
		return NULL;
	}

	return clif;
}

void clif_close(struct clif *clif)
{
	close(clif->s);
	free(clif);
}





int clif_request(struct clif *clif, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len))
{
	struct timeval tv;
	int res;
	fd_set rfds;
	const char *_cmd;
	size_t _cmd_len;

	_cmd = cmd;
	_cmd_len = cmd_len;

	if (send(clif->s, _cmd, _cmd_len, 0) < 0)
		return -1;

	for (;;) {
		tv.tv_sec = CMD_RESPONSE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(clif->s, &rfds);
		res = select(clif->s + 1, &rfds, NULL, NULL, &tv);
		if (FD_ISSET(clif->s, &rfds)) {
			res = recv(clif->s, reply, *reply_len, 0);
			if (res < 0) {
				printf("less then zero\n");
				return res;
			}
			if ((res > 0 && reply[MSG_TYPE] == EVENT_MSG) ||
			   ((reply[MSG_TYPE] == MOD_CMD) &&
			    (res > MOD_MSG_TYPE) &&
			    (reply[MOD_MSG_TYPE] == EVENT_MSG))) {
				/* This is an unsolicited message from
				 * lldpad, not the reply to the
				 * request. Use msg_cb to report this to the
				 * caller. */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated. */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			*reply_len = res;
			break;
		} else {
			printf("timeout\n");
			return -2;
		}
	}
	return 0;
}


static int clif_attach_helper(struct clif *clif, char *tlvs_hex, int attach)
{
	char *buf;
	char rbuf[10];
	int ret;
	size_t len = 10;

	/* Allocate maximum buffer usage */
	if (tlvs_hex && attach) {
		buf = malloc(sizeof(char)*(strlen(tlvs_hex) + 2));
		if (!buf)
			return -1;
		sprintf(buf, "%s%s","A",tlvs_hex);
	} else if (attach) {
		buf = malloc(sizeof(char) * 2);
		if (!buf)
			return -1;
		sprintf(buf, "A");
	} else {
		buf = malloc(sizeof(char) * 2);
		if (!buf)
			return -1;
		sprintf(buf, "D");
	}

	ret = clif_request(clif, buf, strlen(buf), rbuf, &len, NULL);
	free(buf);
	if (ret < 0)
		return ret;
	if (len == 4 && memcmp(rbuf, "R00", 3) == 0)
		return 0;
	return -1;
}


int clif_attach(struct clif *clif, char *tlvs_hex)
{
	return clif_attach_helper(clif, tlvs_hex, 1);
}


int clif_detach(struct clif *clif)
{
	return clif_attach_helper(clif, NULL, 0);
}



int clif_recv(struct clif *clif, char *reply, size_t *reply_len)
{
	int res;

	res = recv(clif->s, reply, *reply_len, 0);
	if (res < 0)
		return res;
	*reply_len = res;
	return 0;
}


int clif_pending_wait(struct clif *clif, int waittime)
{
	struct timeval tv;
	fd_set rfds;
	tv.tv_sec = waittime;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(clif->s, &rfds);
	select(clif->s + 1, &rfds, NULL, NULL, &tv);
	return FD_ISSET(clif->s, &rfds);
}

int clif_pending(struct clif *clif)
{
	return clif_pending_wait(clif, 0);
}

int clif_get_fd(struct clif *clif)
{
	return clif->s;
}

/*
 * Get PID of lldpad from 'ping' command
 */
pid_t clif_getpid(void)
{
	struct clif *clif_conn;
	char buf[MAX_CLIF_MSGBUF];
	size_t len = sizeof(buf);
	char *ppong;
	int ret;
	pid_t lldpad = 0;		/* LLDPAD process identifier */

	clif_conn = clif_open();
	if (!clif_conn) {
		fprintf(stderr, "couldn't connect to lldpad\n");
		return 0;
	}
	if (clif_attach(clif_conn, NULL)) {
		fprintf(stderr, "failed to attach to lldpad\n");
		clif_close(clif_conn);
		return 0;
	}
	ret = clif_request(clif_conn, "P", 1, buf, &len, NULL);
	if (ret == -2) {
		fprintf(stderr, "connection to lldpad timed out\n");
		goto out;
	}
	if (ret < 0) {
		fprintf(stderr, "ping command failed\n");
		goto out;
	}
	buf[len] = '\0';
	ppong = strstr(buf, "PPONG");		/* Ignore leading chars */
	if (!ppong || sscanf(ppong, "PPONG%d", &lldpad) != 1) {
		fprintf(stderr, "error parsing pid of lldpad\n");
		lldpad = 0;
	}
out:
	clif_detach(clif_conn);
	clif_close(clif_conn);
	return lldpad;
}

/*
 * Command line interface for vdp22 module.
 * Includes for lldptool like access to lldpad
 */
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include "include/qbg22.h"
#include "include/qbg_vdp22_clif.h"	/* Defines op_XXXX */
#include <sys/queue.h>			/* Needed by agent.h */
#include "lldp/agent.h"			/* Nearest customer bridge define */

/*
 * Send a command via clif_xxx to lldpad.
 * Return negavite numbers when a send/reply error occurs.
 * Lldpad returns cmd_success for success and cmd_xxx for failure.
 */
static int tool_send(struct clif *connp, char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len, int *lldpad_rc)
{
	int rc;

	*lldpad_rc = 0;
	rc = clif_request(connp, cmd, cmd_len, reply, reply_len, NULL);
	if (!rc) {
		if (1 != sscanf(reply, "R%02x", lldpad_rc))
			rc = -3;
	}
	return rc;
}

/*
 * Prepend the lldpad fan out information in front of the command.
 * We use the vsi parameter.
 */
static int hdr_set(char *ifname, char *s, size_t sz, unsigned int tlvid,
		   char *cmd, size_t cmd_len)
{
	int rc;

	/* All command messages begin this way */
	rc = snprintf(s, sz, "%c%08x%c%1x%02x%08x%02zx%s%02x%08x03vsi%04zx%s",
		MOD_CMD, LLDP_MOD_VDP22, CMD_REQUEST, CLIF_MSG_VERSION,
		cmd_settlv, op_arg | op_argval | op_config,
		strlen(ifname), ifname, NEAREST_CUSTOMER_BRIDGE, tlvid,
		cmd_len, cmd);
	return (rc < 0 || rc > (int)sz) ? -EFBIG : 0;
}

/*
 * Remove all whitespace and nonprintable characters from string.
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

/*
 * Send a VSI command to the vdp22 module and expect a reply. The reply can be
 * an aknowledgement (error code 0) or an error code != 0 which means the
 * command contained an error and was not accepted.
 */
int clif_vsi(struct clif *connp, char *ifname, unsigned int tlvid,
	     char *cmd, char *reply, size_t *reply_len)
{
	int rc, resp;
	char cmd2[MAX_CLIF_MSGBUF];

	kill_white(cmd);
	rc = hdr_set(ifname, cmd2, sizeof(cmd2), tlvid, cmd, strlen(cmd));
	if (rc)
		return rc;
	rc = tool_send(connp, cmd2, strlen(cmd2), reply, reply_len, &resp);
	if (!rc)
		rc = resp;
	return rc;
}

/*
 * Test if this is an event message from vdp22 module.
 */
static bool test_evt(char *msg, size_t *msg_len)
{
	bool is_evt = true;
	unsigned int module;

	if (*msg_len < 12 || msg[MSG_TYPE] != MOD_CMD
	    || msg[MOD_MSG_TYPE] != EVENT_MSG
	    || sscanf(&msg[MSG_TYPE + 1], "%08x", &module) != 1
	    || module != LLDP_MOD_VDP22)
		is_evt = false;
	return is_evt;
}

/*
 * Wait for an event message from lldpad module. After checking for the correct
 * event message, the header of the event message is removed.
 *
 * Returns
 * <0 on error or time out.
 * =0 number of bytes on successful message reception (in reply_len parameter).
 */
#define	EVTHEADER	12		/* # of bytes in event message as hdr */
int clif_vsievt(struct clif *clif, char *reply, size_t *reply_len, int wait)
{
	if (clif == NULL || wait < 0)
		return -EINVAL;
	if (clif_pending_wait(clif, wait)) {
		if (clif_recv(clif, reply, reply_len) == 0) {
			if (test_evt(reply, reply_len)) {
				*reply_len -= EVTHEADER;
				memmove(reply, reply + EVTHEADER, *reply_len);
				reply[*reply_len] = '\0';
				return 0;
			} else
				return -EBADF;
		} else
			return -EIO;
	}
	return -EAGAIN;
}
/*
 * Send a VSI command to the vdp22 mode and expect a reply. The reply can
 * an aknowledgement (error code 0) or an error code != 0 which means the
 * command contained an error and was not accepted.
 *
 * Wait for the event message from lldpad to return the VSI association data
 * from the switch
 */
int clif_vsiwait(struct clif *connp, char *ifname, unsigned int tlvid,
		 char *cmd, char *reply, size_t *reply_len, int wait)
{
	int rc;
	size_t reply_len2 = *reply_len;

	rc = clif_vsi(connp, ifname, tlvid, cmd, reply, reply_len);
	if (!rc) {
		rc = clif_vsievt(connp, reply, &reply_len2, wait);
		if (!rc)
			*reply_len = reply_len2;
	}
	return rc;
}
