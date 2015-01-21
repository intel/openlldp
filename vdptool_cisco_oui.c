/*******************************************************************************

  Implementation of Cisco Specific OUI for vdptool
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
#include "vdp_cisco.h"

bool cisco_oui_encode_hndlr(char *dst, char *src, int len)
{
	char *src_temp = strdup(src);
	char *key, *data;
	bool flag = false;

	if (!src_temp)
		return false;
	key = src_temp;
	data = strchr(key, '=');
	if (!data) {
		free(src_temp);
		return false;
	}
	*data = '\0';
	data++;
	if ((!strcmp(key, CISCO_OUI_NAME_ARG_STR)) ||
	    (!strcmp(key, CISCO_OUI_L3V4ADDR_ARG_STR)) ||
	    (!strcmp(key, CISCO_OUI_NAME_UUID_ARG_STR))) {
		snprintf(dst, MAX_OUI_DATA_LEN - len, "%02x%s%04x%s",
			 (unsigned int)strlen(key), key,
			 (unsigned int)strlen(data), data);
		flag = true;
	} else
		printf("Incorrect Cisco OUI %s\n", key);
	free(src_temp);
	return flag;
}

