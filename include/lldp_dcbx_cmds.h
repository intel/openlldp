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

#ifndef CLIF_CMDS_H
#define CLIF_CMDS_H

#include <sys/un.h>
#include <stdbool.h>
#include "clif_msgs.h"

struct arg_handlers *dcbx_get_arg_handlers();
void dont_advertise_dcbx_all(char *ifname, bool ad);

#define CLIF_RSP_MSG_OFF    0

/* Client interface DCB command codes */
#define CMD_GET_CONFIG  1
#define CMD_SET_CONFIG  2
#define CMD_GET_OPER    3
#define CMD_GET_PEER    4

/* Client interface Feature codes */
#define FEATURE_DCB    1
#define FEATURE_PG     2
#define FEATURE_PFC    3
#define FEATURE_BCN    4
#define FEATURE_APP    5
#define FEATURE_LLINK  6
#define FEATURE_DCBX       0xfe
#define FEATURE_PG_DESC    0xff

/* DCB event message offsets (after port id field) */
#define EV_FEATURE_OFF      0
#define EV_SUBTYPE_OFF      2
#define EV_OP_MODE_CHG_OFF  4
#define EV_OP_CFG_CHG_OFF   5

/* Client interface DCB command message field offsets */
#define CLIF_CMD_OFF    0
#define CLIF_CMD_LEN    1
#define DCB_VER_OFF     (CLIF_CMD_OFF + CLIF_CMD_LEN)
#define DCB_VER_LEN     1
#define DCB_CMD_OFF     (DCB_VER_OFF + DCB_VER_LEN)
#define DCB_CMD_LEN     2
#define DCB_FEATURE_OFF (DCB_CMD_OFF + DCB_CMD_LEN)
#define DCB_FEATURE_LEN 2
#define DCB_SUBTYPE_OFF (DCB_FEATURE_OFF + DCB_FEATURE_LEN)
#define DCB_SUBTYPE_LEN 2
#define DCB_PORTLEN_OFF (DCB_SUBTYPE_OFF + DCB_SUBTYPE_LEN)
#define DCB_PORTLEN_LEN 2
#define DCB_PORT_OFF    (DCB_PORTLEN_OFF + DCB_PORTLEN_LEN)

/* DCBX configuration commands do not need to have a port field */
#define DCBX_CFG_OFF (DCB_FEATURE_OFF + DCB_FEATURE_LEN)

/* Offset into the DCB protocol data section of the client
 * interface message.
 * GetConfig and SetConfig commands */
#define CFG_ENABLE      0
#define CFG_ADVERTISE   1
#define CFG_WILLING     2
#define CFG_LEN         3

/* Offset into the DCB protocol data section of the client
 * interface message.
 * GetOper commands */
#define OPER_OPER_VER   0
#define OPER_MAX_VER    2
#define OPER_ERROR      4
#define OPER_OPER_MODE  6
#define OPER_SYNCD      7
#define OPER_LEN        8

/* Offset into the DCB protocol data section of the client
 * interface message.
 * GetPeer command */
#define PEER_ENABLE     0
#define PEER_WILLING    1
#define PEER_OPER_VER   2
#define PEER_MAX_VER    4
#define PEER_ERROR      6
#define PEER_SUBTYPE    7
#define PEER_LEN        8

/* DCB status data offset */
#define DCB_STATE       0

/* DCB State configuration data length */
#define CFG_DCB_DLEN    1

/* DCBX Version configuration data offset */
#define DCBX_VERSION  0

/* DCBX configuration data length
 * Does not include the Operational version */
#define CFG_DCBX_DLEN   1

/* Priority Flow Control configuration data offsets */
#define PFC_UP(i)         (i)
#define PFC_NUM_TC        (PFC_UP(8))

/* Priority Flow Control configuration data length */
#define CFG_PFC_DLEN      (PFC_NUM_TC+1)

/* Priority Groups configuration data offsets */
#define PG_UP2TC(i)       (i)
#define PG_PG_PCNT(i)     (PG_UP2TC(8)     + (2*i))
#define PG_UP_PGID(i)     (PG_PG_PCNT(8)   +    i)
#define PG_UP_PCNT(i)     (PG_UP_PGID(8)   + (2*i))
#define PG_UP_STRICT(i)   (PG_UP_PCNT(8)   +    i)
#define PG_UP_NUM_TC      (PG_UP_STRICT(8))

/* Priority Groups configuration data length */
#define CFG_PG_DLEN      (PG_UP_NUM_TC+1)

/* Application configuration data offsets */
#define APP_LEN           0
#define APP_DATA          2

/* Priority group description data offsets */
#define PG_DESC_PGID          0
#define PG_DESC_LEN           1
#define PG_DESC_DATA          3

#define PG_DESC_GET_DLEN      1
#define PG_DESC_SET_DLEN      3


/* Logical link data offsets */
#define LLINK_STATUS          0
#define LLINK_DLEN            1

#define CLIF_NOT_SUPPLIED 'x'

#define CHANGED   "changed"
#define NOCHANGE   "no change"

#endif /* CLIF_CMDS_H */
