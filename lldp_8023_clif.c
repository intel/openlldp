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
#include "lldp_mod.h"
#include "lldptool.h"
#include "lldp.h"
#include "lldp_8023.h"
#include "lldp_8023_clif.h"

void print_mac_phy(u16, char *info);
void print_power_mdi(u16, char *info);
void print_link_agg(u16, char *info);
void print_mtu(u16, char *info);
int ieee8023_print_help();

u32 ieee8023_lookup_tlv_name(char *tlvid_str);

static const struct lldp_mod_ops ieee8023_ops_clif = {
	.lldp_mod_register 	= ieee8023_cli_register,
	.lldp_mod_unregister 	= ieee8023_cli_unregister,
	.print_tlv		= ieee8023_print_tlv,
	.lookup_tlv_name	= ieee8023_lookup_tlv_name,
	.print_help		= ieee8023_print_help,
};

struct type_name_info ieee8023_tlv_names[] = {
	{ (LLDP_MOD_8023 << 8) | LLDP_8023_MACPHY_CONFIG_STATUS,
		"MAC/PHY Configuration Status TLV",
		"macPhyCfg", print_mac_phy },

	{ (LLDP_MOD_8023 << 8) | LLDP_8023_POWER_VIA_MDI,
		"Power via MDI TLV",
		"powerMdi",  print_power_mdi },

	{ (LLDP_MOD_8023 << 8) | LLDP_8023_LINK_AGGREGATION,
		"Link Aggregation TLV",
		"linkAgg",   print_link_agg },

	{ (LLDP_MOD_8023 << 8) | LLDP_8023_MAXIMUM_FRAME_SIZE,
		"Maximum Frame Size TLV",
		"MTU",       print_mtu },

	{ INVALID_TLVID,     NULL,        NULL }
};

int ieee8023_print_help()
{
	struct type_name_info *tn = &ieee8023_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tn->key && strlen(tn->key) && tn->name) {
			printf("   %s", tn->key);
			if (strlen(tn->key)+3 <= 8)
				printf("\t");
			printf("\t: %s\n", tn->name);
		}
		tn++;
	}
	
	return 0;
}

struct lldp_module *ieee8023_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		goto out_err;
	}
 	mod->id = LLDP_MOD_8023;
	mod->ops = &ieee8023_ops_clif;

	return mod;
out_err:
	return NULL;
}

void ieee8023_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

void print_mac_phy(u16 len, char *info)
{
	u8 autoneg_status;
	u16 pmd_autoneg_cap;
	u16 mau_type;

	if (len != 5) {
		printf("Bad MAC/PHY TLV: %*.*s\n",
			len*2, len*2, info);
		return;
	}

	hexstr2bin(info, (u8 *)&autoneg_status, sizeof(autoneg_status));
	hexstr2bin(info+2, (u8 *)&pmd_autoneg_cap, sizeof(pmd_autoneg_cap));
	pmd_autoneg_cap = ntohs(pmd_autoneg_cap);
	hexstr2bin(info+6, (u8 *)&mau_type, sizeof(mau_type));
	mau_type = ntohs(mau_type);

	printf("Auto-negotiation %s and %s\n",
		(autoneg_status & 0x01) ? "supported" : "not supported",
		(autoneg_status & 0x02) ? "enabled" : "not enabled");

	printf("\tPMD auto-negotiation capabilities: 0x%04x\n",
	       pmd_autoneg_cap);

	/* See dot3MauType IETF RFC 3636 */
	printf("\tMAU type:");
	switch (mau_type) {
	case 1:
		printf(" AUI");
		break;
	case 2:
		printf(" 10 Base5");
		break;
	case 3:
		printf(" FOIRL");
		break;
	case 4:
		printf(" 10 Base2");
		break;
	case 5:
		printf(" 10 BaseT");
		break;
	case 6:
		printf(" 10 BaseFP");
		break;
	case 7:
		printf(" 10 BaseFB");
		break;
	case 8:
		printf(" 10 BaseFL");
		break;
	case 9:
		printf(" 10 Broad 36");
		break;
	case 10:
		printf(" 100 BaseTHD");
		break;
	case 11:
		printf(" 100 BaseTFD");
		break;
	case 12:
		printf(" 100 BaseFLHD");
		break;
	case 13:
		printf(" 100 BaseFLFD");
		break;
	case 14:
		printf(" 100 BaseT4");
		break;
	case 15:
		printf(" 100 BaseTXHD");
		break;
	case 16:
		printf(" 100 BaseTXFD");
		break;
	case 17:
		printf(" 100 BaseFXHD");
		break;
	case 18:
		printf(" 100 BaseFXFD");
		break;
	case 19:
		printf(" 100 BaseT2HD");
		break;
	case 20:
		printf(" 100 BaseT2FD");
		break;
	case 21:
		printf(" 1000 BaseXHD");
		break;
	case 22:
		printf(" 1000 BaseXFD");
		break;
	case 23:
		printf(" 1000 BaseLXHD");
		break;
	case 24:
		printf(" 1000 BaseLXFD");
		break;
	case 25:
		printf(" 1000 BaseSXHD");
		break;
	case 26:
		printf(" 1000 BaseSXFD");
		break;
	case 27:
		printf(" 1000 BaseCXHD");
		break;
	case 28:
		printf(" 1000 BaseCXFD");
		break;
	case 29:
		printf(" 1000 BaseTHD");
		break;
	case 30:
		printf(" 1000 BaseTFD");
		break;
	case 31:
		printf(" 10G BaseX");
		break;
	case 32:
		printf(" 10G BaseLX4");
		break;
	case 33:
		printf(" 10G BaseR");
		break;
	case 34:
		printf(" 10G BaseER");
		break;
	case 35:
		printf(" 10G BaseLR");
		break;
	case 36:
		printf(" 10G BaseSR");
		break;
	case 37:
		printf(" 10G BaseW");
		break;
	case 38:
		printf(" 10G BaseEW");
		break;
	case 39:
		printf(" 10G BaseLW");
		break;
	case 40:
		printf(" 10G BaseSW");
		break;
	default:
		printf(" Unknown [0x%04x]", mau_type);
		break;
	}

	printf("\n");
}

void print_power_mdi(u16 len, char *info)
{
	u8 mdi_power;
	u8 pse_power;
	u8 power_class;

	if (len != 3) {
		printf("Bad Power Via MDI TLV: %*.*s\n",
			len*2, len*2, info);
		return;
	}

	hexstr2bin(info, (u8 *)&mdi_power, sizeof(mdi_power));
	hexstr2bin(info+2, (u8 *)&pse_power, sizeof(pse_power));
	hexstr2bin(info+4, (u8 *)&power_class, sizeof(power_class));

	printf("Port class %s", (mdi_power & 0x01) ? "PSE" : "PD");
	printf(", PSE MDI power %ssupported", (mdi_power & 0x02) ? "" : "not ");
	if (mdi_power & 0x02)
		printf(" and %s", (mdi_power & 0x04) ? "enabled" : "disabled");
	printf(", PSE pairs %scontrollable", (mdi_power & 0x08) ? "" : "not ");

	/* pethPsePortPowerPair - IETF RFC 3621 */
	printf(", PSE Power pair: ");
	if (pse_power == 1)
		printf("signal");
	else if (pse_power == 2)
		printf("spare");
	else
		printf("unkwown [%d]", pse_power);

	/* pethPsePortPowerClassifications - IETF RFC 3621 */
	printf(", Power class %d\n", power_class+1);
}

void print_link_agg(u16 len, char *info)
{
	u8 agg_status;
	u32 agg_portid;

	if (len != 5) {
		printf("Bad Link Aggregation TLV: %*.*s\n",
			len*2, len*2, info);
		return;
	}

	hexstr2bin(info, (u8 *)&agg_status, sizeof(agg_status));
	hexstr2bin(info+2, (u8 *)&agg_portid, sizeof(agg_portid));
	agg_portid = ntohl(agg_portid);

	printf("Aggregation %scapable\n", (agg_status & 0x01) ? "":"not ");
	printf("\tCurrently %saggregated\n", (agg_status & 0x02) ? "":"not ");

	printf("\tAggregated Port ID: %d\n", agg_portid);
}

void print_mtu(u16 len, char *info)
{
	u16 mtu;

	hexstr2bin(info, (u8 *)&mtu, sizeof(mtu));
	mtu = ntohs(mtu);
	printf("%d\n", mtu);
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int ieee8023_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &ieee8023_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n", tn->name);
			if (tn->print_info) {
				printf("\t");
				tn->print_info(len-4, info);
			}
			return 1;
		}
		tn++;
	}
	
	return 0;
}

u32 ieee8023_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &ieee8023_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}
