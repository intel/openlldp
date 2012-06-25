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

#ifndef _CLIF_MSGS_H
#define _CLIF_MSGS_H

#include <asm/types.h>
#include "clif_sock.h"
#include "lldpad_status.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif

/* Client interface versions */
/* Version 2
 *   DCBX subtype field added to peer commands
 *   Priority Group feature adds 'number of TC's supported'
 *   Priority Flow Control feature adds 'number of TC's supported'
*/
#define CLIF_EV_VERSION 2
#define CLIF_MSG_VERSION 3
#define CLIF_RSP_VERSION CLIF_MSG_VERSION

/* Minimum DCB CLIF MSG version we can resolve */
#define CLIF_DCBMSG_VERSION 2

/* Client interface global command codes */
#define UNKNOWN_CMD  '.'
#define PING_CMD     'P'
#define LEVEL_CMD    'L'
#define ATTACH_CMD   'A'
#define DETACH_CMD   'D'
#define DCB_CMD      'C'
#define MOD_CMD      'M'
#define EVENT_MSG    'E'
#define CMD_RESPONSE 'R'
#define CMD_REQUEST  DCB_CMD

/* Remote Change Event ByteCode */
#define LLDP_RCHANGE 1

/* Offsets in client interface module request message
 */
#define	MOD_ID 1

/* Generic client interface field offsets */
#define MSG_TYPE        0
#define MOD_MSG_TYPE    9  /* location of MSG_TYPE in a module message */

/* Client interface event message field offsets */
#define EV_MSG_OFF      0
#define EV_LEVEL_OFF    1
#define EV_GENMSG_OFF   2  /* for unformatted non-DCB event messages */
#define EV_VERSION_OFF  2  /* for DCB event messages */
#define EV_PORT_LEN_OFF 3
#define EV_PORT_LEN_LEN 2
#define EV_PORT_ID_OFF  (EV_PORT_LEN_OFF + EV_PORT_LEN_LEN)

/* Offsets in client interface request messages
 * Module message type and module id
 */
#define MSG_TYPE   0   /* message type i.e. 'C' */
#define MSG_VER    1   /* message version */
#define CMD_CODE   2   /* command code */
#define CMD_OPS    4   /* command options */
#define CMD_IF_LEN 12  /* length of ifname field, '00' is ok */
#define CMD_IF     14  /* ifname field */

/* Client interface response message field offsets */
#define CLIF_STAT_OFF    1
#define CLIF_STAT_LEN    2
#define CLIF_RSP_OFF     (CLIF_STAT_OFF + CLIF_STAT_LEN)

/* max buffer length needed for a field with an unsigned char length */
#define MAX_U8_BUF 256

/* max buffer length for a clif message */
#define MAX_CLIF_MSGBUF 4096

struct cmd {
	__u8 cmd;
	__u32 module_id;
	__u32 ops;
	__u32 tlvid;
	__u8 type;
	char ifname[IFNAMSIZ+1];
	char obuf[MAX_CLIF_MSGBUF];
};

enum {
	MSG_MSGDUMP,
	MSG_DEBUG,
	MSG_INFO,
	MSG_WARNING,
	MSG_ERROR,
	MSG_EVENT
};

#define MSG_DCB MSG_EVENT

#define SHOW_NO_OUTPUT 0x00
#define SHOW_OUTPUT    0x01
#define SHOW_RAW       0x02
#define SHOW_RAW_ONLY  0x04

#define INVALID_TLVID 127

struct type_name_info {
	__u32 type;
	char *name;   /* printable name */
	char *key;    /* key word */
	void (* print_info)(__u16, char *);
	void (* get_info)(__u16, char *);
};

#define LLDP_ARG 0x00
#define TLV_ARG 0x01

struct arg_handlers {
	char *arg;
	int arg_class;
	int (*handle_get)(struct cmd *, char *, char *, char *, int);
	int (*handle_set)(struct cmd *, char *, char *, char *, int);
	int (*handle_test)(struct cmd *, char *, char *, char *, int);
};

#endif
