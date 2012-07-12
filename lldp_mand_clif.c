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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "lldp.h"
#include "lldp_mod.h"
#include "lldp_mand.h"
#include "lldp_mand_clif.h"
#include "clif_msgs.h"

void print_port_id(u16, char *info);
void print_chassis_id(u16, char *info);
void print_ttl(u16, char *info);
u32 mand_lookup_tlv_name(char *tlvid_str);
int mand_print_help();

static const struct lldp_mod_ops mand_ops_clif = {
	.lldp_mod_register 	= mand_cli_register,
	.lldp_mod_unregister 	= mand_cli_unregister,
	.print_tlv		= mand_print_tlv,
	.lookup_tlv_name	= mand_lookup_tlv_name,
	.print_help		= mand_print_help,
};


struct type_name_info mand_tlv_names[] = {
	{	.type = END_OF_LLDPDU_TLV,
		.name = "End of LLDPDU TLV", .key = "", },
	{	.type = CHASSIS_ID_TLV,
		.name = "Chassis ID TLV", .key = "chassisID",
		.print_info = print_chassis_id, },
	{	.type = PORT_ID_TLV,
		.name = "Port ID TLV", .key = "portID",
		.print_info = print_port_id, },
	{	.type = TIME_TO_LIVE_TLV,
		.name = "Time to Live TLV", .key = "TTL",
		.print_info = print_ttl, },
	{	.type = INVALID_TLVID, }
};

int mand_print_help()
{
	struct type_name_info *tn = &mand_tlv_names[0];

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

struct lldp_module *mand_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		goto out_err;
	}
 	mod->id = LLDP_MOD_MAND;
	mod->ops = &mand_ops_clif;

	return mod;
out_err:
	return NULL;
}

void mand_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

void print_chassis_id(u16 len, char *info)
{
	u8 subtype;
	u8 addrnum;
	char buf[512];
	int i;

	if (!len || len > 256) {
		printf("Invalid length = %d\n", len);
		return;
	}

	hexstr2bin(info, (u8 *)&subtype, sizeof(subtype));

	memset(buf, 0, sizeof(buf));
	switch (subtype) {
	case CHASSIS_ID_MAC_ADDRESS:
		if (len != 1 + 6)
			return;
		printf("MAC: ");
		for (i = 0; i < 12; i+=2) {
			printf("%2.2s", info + 2 + i);
			if (i < 10)
				printf(":");
			else
				printf("\n");
		}
		break;
	case CHASSIS_ID_NETWORK_ADDRESS:
		if (len <=2) {
			printf("Bad Network Address\n");
			break;
		}

		hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

		switch(addrnum) {
		case MANADDR_IPV4:
			if (len == 6) {
				struct in_addr addr;
				hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
				inet_ntop(AF_INET, (void *)&addr, buf,
					  sizeof(buf));
				printf("IPv4: %s\n", buf);
			} else {
				printf("Bad IPv4: %*.*s\n",
				       2*(len-2), 2*(len-2), info+4);
			}
			break;
		case MANADDR_IPV6:
			if (len == 18) {
				struct in6_addr addr;
				hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
				inet_ntop(AF_INET6, (void *)&addr, buf,
					  sizeof(buf));
				printf("IPv6: %s\n", buf);
			} else {
				printf("Bad IPv6: %*.*s\n",
				       2*(len-2), 2*(len-2), info+4);
			}
			break;
		default:
			printf("Network Address Type %d: %*.*s\n", addrnum,
			       2*(len-2), 2*(len-2), info+2);
			break;
		}
		break;
	case CHASSIS_ID_CHASSIS_COMPONENT:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Chassis Component: %s\n", buf);
		break;
	case CHASSIS_ID_INTERFACE_ALIAS:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("IfAlias: %s\n", buf);
		break;
	case CHASSIS_ID_PORT_COMPONENT:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Port Component: %s\n", buf);
		break;
	case CHASSIS_ID_INTERFACE_NAME:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Ifname: %s\n", buf);
		break;
	case CHASSIS_ID_LOCALLY_ASSIGNED:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Local: %s\n", buf);
		break;
	default:
		printf("Bad Chassis ID: %*.*s\n", 2*len, 2*len, info);
		break;
	}
}

void print_port_id(u16 len, char *info)
{
	u8 subtype;
	u8 addrnum;
	char buf[512];
	int i;

	if (!len || len > 256) {
		printf("Invalid length = %d\n", len);
		return;
	}

	hexstr2bin(info, (u8 *)&subtype, sizeof(subtype));

	memset(buf, 0, sizeof(buf));
	switch (subtype) {
	case PORT_ID_MAC_ADDRESS:
		if (len != 1 + 6)
			return;
		printf("MAC: ");
		for (i = 0; i < 12; i+=2) {
			printf("%2.2s", info + 2 + i);
			if (i < 10)
				printf(":");
			else
				printf("\n");
		}
		break;
	case PORT_ID_NETWORK_ADDRESS:
		if (len <=2) {
			printf("Bad Network Address\n");
			break;
		}

		hexstr2bin(info+2, (u8 *)&addrnum, sizeof(addrnum));

		switch(addrnum) {
		case MANADDR_IPV4:
			if (len == 6) {
				struct in_addr addr;
				hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
				inet_ntop(AF_INET, (void *)&addr, buf,
					  sizeof(buf));
				printf("IPv4: %s\n", buf);
			} else {
				printf("Bad IPv4: %*.*s\n",
				       2*(len-2), 2*(len-2), info+4);
			}
			break;
		case MANADDR_IPV6:
			if (len == 18) {
				struct in6_addr addr;
				hexstr2bin(info+4, (u8 *)&addr, sizeof(addr));
				inet_ntop(AF_INET6, (void *)&addr, buf,
					  sizeof(buf));
				printf("IPv6: %s\n", buf);
			} else {
				printf("Bad IPv6: %*.*s\n",
				       2*(len-2), 2*(len-2), info+4);
			}
			break;
		default:
			printf("Network Address Type %d: %*.*s\n", addrnum,
			       2*(len-2), 2*(len-2), info+2);
			break;
		}
		break;
	case PORT_ID_INTERFACE_ALIAS:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Interface Alias: %s\n", buf);
		break;
	case PORT_ID_PORT_COMPONENT:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Port Component: %s\n", buf);
		break;
	case PORT_ID_INTERFACE_NAME:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Ifname: %s\n", buf);
		break;
	case PORT_ID_LOCALLY_ASSIGNED:
		hexstr2bin(info+2, (u8 *)&buf[0], len-1);
		printf("Local: %s\n", buf);
		break;
	case PORT_ID_AGENT_CIRCUIT_ID:
		printf("Agent Circuit ID: %*.*s\n", 2*(len-1), 2*(len-1),
		       info+2);
		break;
	default:
		printf("Bad Port ID: %*.*s\n", 2*len, 2*len, info);
		break;
	}
}

void print_ttl(UNUSED u16 len, char *info)
{
	u16 ttl;

	hexstr2bin(info, (u8 *)&ttl, sizeof(ttl));
	ttl = ntohs(ttl);
	printf("%d\n", ttl);
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int mand_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &mand_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n", tn->name);
			if (tn->print_info) {
				printf("\t");
				tn->print_info(len, info);
			}
			return 1;
		}
		tn++;
	}
	
	return 0;
}

u32 mand_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &mand_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}
