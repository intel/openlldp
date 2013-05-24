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


int clif_pending(struct clif *clif)
{
	struct timeval tv;
	fd_set rfds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(clif->s, &rfds);
	select(clif->s + 1, &rfds, NULL, NULL, &tv);
	return FD_ISSET(clif->s, &rfds);
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
	size_t len;
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
