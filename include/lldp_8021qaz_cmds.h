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

#ifndef _LLDP_IEEE8021QAZ_CMDS_H
#define _LLDP_IEEE8021QAZ_CMDS_H

#include <sys/un.h>
#include "clif_msgs.h"

#define ARG_WILLING	"willing"
#define ARG_DCBX_MODE	"mode"

/* ETS */
#define ARG_ETS_NUMTCS	"numtcs"
#define ARG_ETS_UP2TC	"up2tc"
#define ARG_ETS_TCBW	"tcbw"
#define ARG_ETS_TSA	"tsa"

/* PFC */
#define ARG_PFC_ENABLED "enabled"
#define ARG_PFC_DELAY	"delay"
#define ARG_PFC_NUMTCS	"numtcs"

/* APP */
#define ARG_APP	    "APP"

struct arg_handlers *ieee8021qaz_get_arg_handlers();

#endif
