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
#include "lldp_util.h"
#include "vdp_cisco.h"

bool cisco_oui_encode_hndlr(char *dst, char *src, size_t len)
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

void cisco_oui_print_decode_hndlr(char *token)
{
	struct in_addr vm_inet;
	char *v4_addr_str;
	unsigned long vm_ip_addr;
	int offset = 0, len;
	u16 data_len;
	u8 key_len;
	enum oui_key_arg oui_argtype;
	char addr[INET_ADDRSTRLEN];

	if (token == NULL)
		return;
	len = strlen(token);
	while (offset < len) {
		hexstr2bin(token, &key_len, sizeof(key_len));
		token += 2;
		offset += 2;
		oui_argtype = get_oui_key(token, key_len);
		token += key_len;
		offset += key_len;
		hexstr2bin(token, (u8 *)&data_len, sizeof(data_len));
		data_len = htons(data_len);
		token += 4;
		offset += 4;
		if ((offset + data_len) > len)
			return;
		switch (oui_argtype) {
		case CISCO_OUI_NAME_ARG:
			printf("\t%s", "VM Name");
			printf(" = %.*s\n", data_len, token);
			break;
		case CISCO_OUI_NAME_UUID_ARG:
			printf("\t%s", "VM UUID");
			printf(" = %.*s\n", data_len, token);
			break;
		case CISCO_OUI_L3V4ADDR_ARG:
			v4_addr_str = calloc(data_len, sizeof(char));
			if (!v4_addr_str)
				return;
			strncpy(v4_addr_str, token, data_len);
			vm_ip_addr = strtoul(v4_addr_str, NULL, 10);
			vm_inet.s_addr = vm_ip_addr;
			if (inet_ntop(AF_INET, &vm_inet, addr, INET_ADDRSTRLEN) == NULL)
				return;
			printf("\t%s", "VM IP Address");
			printf(" = %s\n", addr);
			free(v4_addr_str);
			break;
		default:
			break;
		}
		token += data_len;
		offset += data_len;
	}
}
