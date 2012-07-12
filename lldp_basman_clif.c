/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2010 Intel Corporation.

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
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldp_mod.h"
#include "lldptool.h"
#include "clif_msgs.h"
#include "lldp_basman.h"
#include "lldp_basman_clif.h"

void print_string_tlv(u16, char *info);
void print_capabilities(u16, char *info);
void print_mng_addr(u16, char *info);
u32 basman_lookup_tlv_name(char *tlvid_str);
int basman_print_help();

static const struct lldp_mod_ops basman_ops_clif = {
	.lldp_mod_register 	= basman_cli_register,
	.lldp_mod_unregister 	= basman_cli_unregister,
	.print_tlv		= basman_print_tlv,
	.lookup_tlv_name	= basman_lookup_tlv_name,
	.print_help		= basman_print_help,
};

struct type_name_info basman_tlv_names[] = {
	{	.type = PORT_DESCRIPTION_TLV,
		.name = "Port Description TLV", .key = "portDesc",
		.print_info = print_string_tlv, },
	{	.type = SYSTEM_NAME_TLV,
		.name = "System Name TLV", .key = "sysName",
		.print_info = print_string_tlv, },
	{	.type = SYSTEM_DESCRIPTION_TLV,
		.name = "System Description TLV", .key = "sysDesc",
		.print_info = print_string_tlv, },
	{	.type = SYSTEM_CAPABILITIES_TLV,
		.name = "System Capabilities TLV", .key = "sysCap",
		.print_info = print_capabilities, },
	{	.type = MANAGEMENT_ADDRESS_TLV,
		.name = "Management Address TLV", .key = "mngAddr",
		.print_info = print_mng_addr, },
	{	.type = INVALID_TLVID, }
};

int basman_print_help()
{
	struct type_name_info *tn = &basman_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tn->key && strlen(tn->key) && tn->name) {
			printf("   %s", tn->key);
			if (strlen(tn->key)+3 < 8)
				printf("\t");
			printf("\t: %s\n", tn->name);
		}
		tn++;
	}
	
	return 0;
}

struct lldp_module *basman_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		goto out_err;
	}
 	mod->id = LLDP_MOD_BASIC;
	mod->ops = &basman_ops_clif;

	return mod;
out_err:
	return NULL;
}

void basman_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

void print_string_tlv(u16 len, char *info)
{
	int i;
	for (i = 0; i < 2*len; i+=2)
		printf("%c", hex2int(info+i));
	printf("\n");
}

void print_capability_list(u16 capabilities)
{
	int print_comma = 0;

	if (capabilities & 0x01) {
		printf("Other");
		print_comma = 1;
	}
	if (capabilities & 0x02) {
		printf("%sRepeater", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x04) {
		printf("%sBridge", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x08) {
		printf("%sWLAN Access Point", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x10) {
		printf("%sRouter", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x20) {
		printf("%sTelephone", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x40) {
		printf("%sDOCSIS cable device", (print_comma)?", ":"");
		print_comma = 1;
	}
	if (capabilities & 0x80) {
		printf("%sStation Only", (print_comma)?", ":"");
		print_comma = 1;
	}
}

void print_capabilities(u16 len, char *info)
{
	u16 system_cap;
	u16 enabled_cap;

	if (len != 4) {
		printf("Bad System Capabilities TLV: %*.*s\n",
			2*len, 2*len, info);
		return;
	}

	hexstr2bin(info, (u8 *)&system_cap, sizeof(system_cap));
	system_cap = ntohs(system_cap);
	hexstr2bin(info+4, (u8 *)&enabled_cap, sizeof(enabled_cap));
	enabled_cap = ntohs(enabled_cap);

	printf("System capabilities:  ");
	print_capability_list(system_cap);
	printf("\n");
	printf("\tEnabled capabilities: ");
	print_capability_list(enabled_cap);
	printf("\n");
}

void print_mng_addr(u16 len, char *info)
{
	u8 addrlen;
	u8 addrnum;
	u8 iftype;
	u8 oidlen;
	u32 ifnum;
	u32 offset;
	int i;
	char buf[132];

	if (len < 9 || len > 167) {
		printf("Bad Management Address TLV: %*.*s\n",
			2*len, 2*len, info);
		return;
	}

	hexstr2bin(info, (u8 *)&addrlen, sizeof(addrlen));
	hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

	switch(addrnum) {
	case MANADDR_ALL802:
		if (addrlen != 1 + 6)
			return;
		printf("MAC: ");
		for (i = 0; i < 12; i+=2) {
			printf("%2.2s", info + 4 + i);
			if (i < 10)
				printf(":");
			else
				printf("\n");
		}
		break;
	case MANADDR_IPV4:
		if (addrlen == 5) {
			struct in_addr addr;
			hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
			inet_ntop(AF_INET, (void *)&addr, buf,
				  sizeof(buf));
			printf("IPv4: %s\n", buf);
		} else {
			printf("Bad IPv4: %*.*s\n",
			       2*(addrlen-2), 2*(addrlen-2), info+4);
		}
		break;
	case MANADDR_IPV6:
		if (addrlen == 17) {
			struct in6_addr addr;
			hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
			memset(buf, 0, sizeof(buf));
			inet_ntop(AF_INET6, (void *)&addr, buf,
				  sizeof(buf));
			printf("IPv6: %s\n", buf);
		} else {
			printf("Bad IPv6: %*.*s\n",
			       2*(addrlen-2), 2*(addrlen-2), info+4);
		}
		break;
	default:
		printf("Network Address Type %d: %*.*s\n", addrnum,
		       2*(addrlen-1), 2*(addrlen-1), info+4);
		break;
	}

	offset = 2*(1+addrlen);
	hexstr2bin(info+offset, (u8 *)&iftype, sizeof(iftype));
	offset += 2;
	hexstr2bin(info+offset, (u8 *)&ifnum, sizeof(ifnum));
	offset += 2*sizeof(u32);
	ifnum = ntohl(ifnum);

	switch (iftype) {
	case IFNUM_UNKNOWN:
		printf("Unknown interface subtype: ");
		break;
	case IFNUM_IFINDEX:
		printf("\tIfindex: ");
		break;
	case IFNUM_SYS_PORT_NUM:
		printf("System port number: ");
		break;
	default:
		printf("Bad interface numbering subtype: ");
		break;
	}
	printf("%d\n", ifnum);

	hexstr2bin(info+offset, (u8 *)&oidlen, sizeof(oidlen));
	offset += 2;

	if (oidlen && oidlen <= 128) {
		memset(buf, 0, sizeof(buf));
		hexstr2bin(info+offset, (u8 *)&buf, sizeof(buf));
		printf("OID: %s", buf);
	}
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int basman_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &basman_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n\t", tn->name);
			if (tn->print_info)
				tn->print_info(len, info);
			return 1;
		}
		tn++;
	}
	
	return 0;
}

u32 basman_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &basman_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}
