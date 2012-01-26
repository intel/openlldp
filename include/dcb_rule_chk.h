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

#ifndef _DCB_RULE_CHK_H
#define _DCB_RULE_CHK_H

#include "lldp.h"

#define MAX_USER_PRIORITY       MAX_USER_PRIORITIES
#define MAX_TRAFFIC_CLASS       MAX_TRAFFIC_CLASSES
#define MAX_BW_GROUP            MAX_BANDWIDTH_GROUPS
#define BW_PERCENT              100

/* DCB error Codes */
#define DCB_SUCCESS                  0
#define DCB_ERR_CONFIG              -1
#define DCB_ERR_PARAM               -2

/* Trasmit  and receive Errors */
/* Error in bandwidth group allocation */
#define DCB_TX_ERR_BW_GROUP         -4
#define DCB_RX_ERR_BW_GROUP         -5
/* Error in traffic class bandwidth allocation */
#define DCB_TX_ERR_TC_BW            -6
#define DCB_RX_ERR_TC_BW            -7
/* Traffic class has both link strict and group strict enabled */
#define DCB_TX_ERR_LS_GS            -8
#define DCB_RX_ERR_LS_GS            -9
/* Link strict traffic class has non zero bandwidth */
#define DCB_TX_ERR_LS_BW_NONZERO    -0xA
#define DCB_RX_ERR_LS_BW_NONZERO    -0xB
/* Link strict bandwidth group has non zero bandwidth */
#define DCB_TX_ERR_LS_BWG_NONZERO    -0xC
#define DCB_RX_ERR_LS_BWG_NONZERO    -0xD
/*  Traffic calss has zero bandwidth */
#define DCB_TX_ERR_TC_BW_ZERO       -0xE
#define DCB_RX_ERR_TC_BW_ZERO       -0xF

#define DCB_NOT_IMPLEMENTED          0x7FFFFFFF


#endif /* _DCB_RULE_CHK_H */

