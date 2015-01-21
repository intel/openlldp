/*******************************************************************************

  Implementation of OUI Functionality for VDP2.2
  This file contains the exported functions from VDP to the OUI handlers file.
  Copyright (c) 2012-2014 by Cisco Systems, Inc.

  Author(s): Padmanabhan Krishnan <padkrish at cisco dot com>

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
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "messages.h"
#include "lldp_util.h"
#include "qbg_vdp22.h"
#include "qbg_utils.h"
#include "qbg_vdp22_oui.h"

unsigned char vdp22_oui_get_vsi22_fmt(void *vsi_data)
{
	if (vsi_data != NULL)
		return ((struct vsi22 *)(vsi_data))->vsi_fmt;
	LLDPAD_ERR("%s: NULL Arg\n", __func__);
	return 0;
}

unsigned char *vdp22_oui_get_vsi22_len(void *vsi_data, unsigned char *len)
{
	if ((vsi_data != NULL) && (len != NULL)) {
		*len = VDP22_IDSZ;
		return ((struct vsi22 *)(vsi_data))->vsi;
	}
	LLDPAD_ERR("%s: NULL Arg\n", __func__);
	return NULL;
}

int oui_vdp_str2uuid(unsigned char *to, char *buffer, size_t max)
{
	return vdp_str2uuid(to, buffer, max);
}

int oui_vdp_hexstr2bin(const char *hex, unsigned char *buf, size_t len)
{
	return hexstr2bin(hex, buf, len);
}
