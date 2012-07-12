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
#include "clif_msgs.h"
#include "lldp.h"
#include "lldp_8023.h"
#include "lldp_8023_clif.h"
#include "lldp_util.h"

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
	{	.type = (LLDP_MOD_8023 << 8) | LLDP_8023_MACPHY_CONFIG_STATUS,
		.name = "MAC/PHY Configuration Status TLV", .key = "macPhyCfg",
		.print_info = print_mac_phy, },
	{	.type = (LLDP_MOD_8023 << 8) | LLDP_8023_POWER_VIA_MDI,
		.name = "Power via MDI TLV", .key = "powerMdi",
		.print_info = print_power_mdi, },
	{	.type = (LLDP_MOD_8023 << 8) | LLDP_8023_LINK_AGGREGATION,
		.name = "Link Aggregation TLV", .key = "linkAgg",
		.print_info = print_link_agg, },
	{	.type = (LLDP_MOD_8023 << 8) | LLDP_8023_MAXIMUM_FRAME_SIZE,
		.name = "Maximum Frame Size TLV", .key = "MTU",
		.print_info = print_mtu, },
	{	.type = INVALID_TLVID, }
};

int ieee8023_print_help()
{
	struct type_name_info *tn = &ieee8023_tlv_names[0];

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

	/* See dot3MauType IETF RFC 4836 && */
	/*                 IANA MAU MIB     */
	printf("\tMAU type:");
	switch (mau_type) {
	case DOT3MAUTYPE_AUI:
		printf(" AUI");
		break;
	case DOT3MAUTYPE_10Base5:
		printf(" 10 Base5");
		break;
	case DOT3MAUTYPE_Foirl:
		printf(" FOIRL");
		break;
	case DOT3MAUTYPE_10Base2:
		printf(" 10 Base2");
		break;
	case DOT3MAUTYPE_10BaseT:
		printf(" 10 BaseT");
		break;
	case DOT3MAUTYPE_10BaseFP:
		printf(" 10 BaseFP");
		break;
	case DOT3MAUTYPE_10BaseFB:
		printf(" 10 BaseFB");
		break;
	case DOT3MAUTYPE_10BaseFL:
		printf(" 10 BaseFL");
		break;
	case DOT3MAUTYPE_10Broad36:
		printf(" 10 Broad 36");
		break;
	case DOT3MAUTYPE_10BaseTHD:
		printf(" 100 BaseTHD");
		break;
	case DOT3MAUTYPE_10BaseTFD:
		printf(" 100 BaseTFD");
		break;
	case DOT3MAUTYPE_10BaseFLHD:
		printf(" 100 BaseFLHD");
		break;
	case DOT3MAUTYPE_10BaseFLFD:
		printf(" 100 BaseFLFD");
		break;
	case DOT3MAUTYPE_100BaseT4:
		printf(" 100 BaseT4");
		break;
	case DOT3MAUTYPE_100BaseTXHD:
		printf(" 100 BaseTXHD");
		break;
	case DOT3MAUTYPE_100BaseTXFD:
		printf(" 100 BaseTXFD");
		break;
	case DOT3MAUTYPE_100BaseFXHD:
		printf(" 100 BaseFXHD");
		break;
	case DOT3MAUTYPE_100BaseFXFD:
		printf(" 100 BaseFXFD");
		break;
	case DOT3MAUTYPE_100BaseT2HD:
		printf(" 100 BaseT2HD");
		break;
	case DOT3MAUTYPE_100BaseT2FD:
		printf(" 100 BaseT2FD");
		break;
	case DOT3MAUTYPE_1000BaseXHD:
		printf(" 1000 BaseXHD");
		break;
	case DOT3MAUTYPE_1000BaseXFD:
		printf(" 1000 BaseXFD");
		break;
	case DOT3MAUTYPE_1000BaseLXHD:
		printf(" 1000 BaseLXHD");
		break;
	case DOT3MAUTYPE_1000BaseLXFD:
		printf(" 1000 BaseLXFD");
		break;
	case DOT3MAUTYPE_1000BaseSXHD:
		printf(" 1000 BaseSXHD");
		break;
	case DOT3MAUTYPE_1000BaseSXFD:
		printf(" 1000 BaseSXFD");
		break;
	case DOT3MAUTYPE_1000BaseCXHD:
		printf(" 1000 BaseCXHD");
		break;
	case DOT3MAUTYPE_1000BaseCXFD:
		printf(" 1000 BaseCXFD");
		break;
	case DOT3MAUTYPE_1000BaseTHD:
		printf(" 1000 BaseTHD");
		break;
	case DOT3MAUTYPE_1000BaseTFD:
		printf(" 1000 BaseTFD");
		break;
	case DOT3MAUTYPE_10GBaseX:
		printf(" 10G BaseX");
		break;
	case DOT3MAUTYPE_10GBaseLX4:
		printf(" 10G BaseLX4");
		break;
	case DOT3MAUTYPE_10GBaseR:
		printf(" 10G BaseR");
		break;
	case DOT3MAUTYPE_10GBaseER:
		printf(" 10G BaseER");
		break;
	case DOT3MAUTYPE_10GBaseLR:
		printf(" 10G BaseLR");
		break;
	case DOT3MAUTYPE_10GBaseSR:
		printf(" 10G BaseSR");
		break;
	case DOT3MAUTYPE_10GBaseW:
		printf(" 10G BaseW");
		break;
	case DOT3MAUTYPE_10GBaseEW:
		printf(" 10G BaseEW");
		break;
	case DOT3MAUTYPE_10GBaseLW:
		printf(" 10G BaseLW");
		break;
	case DOT3MAUTYPE_10GBaseSW:
		printf(" 10G BaseSW");
		break;
	case DOT3MAUTYPE_10GBaseCX4:
		printf(" 10G BaseCX4");
		break;
	case DOT3MAUTYPE_2BaseTL:
		printf(" 2 BaseTL");
		break;
	case DOT3MAUTYPE_10PassTS:
		printf(" 10 PassTS");
		break;
	case DOT3MAUTYPE_100BaseBX10D:
		printf(" 100 BaseBX10D");
		break;
	case DOT3MAUTYPE_100BaseBX10U:
		printf(" 100 BaseBX10U");
		break;
	case DOT3MAUTYPE_100BaseLX10:
		printf(" 100 BaseLX10");
		break;
	case DOT3MAUTYPE_1000BaseBX10D:
		printf(" 1000 BaseBX10D");
		break;
	case DOT3MAUTYPE_1000BaseBX10U:
		printf(" 1000 BaseBX10U");
		break;
	case DOT3MAUTYPE_1000BaseLX10:
		printf(" 1000 BaseLX10");
		break;
	case DOT3MAUTYPE_1000BasePX10D:
		printf(" 1000 BasePX10D");
		break;
	case DOT3MAUTYPE_1000BasePX10U:
		printf(" 1000 BasePX10U");
		break;
	case DOT3MAUTYPE_1000BasePX20D:
		printf(" 1000 BasePX20D");
		break;
	case DOT3MAUTYPE_1000BasePX20U:
		printf(" 1000 BasePX20U");
		break;
	case DOT3MAUTYPE_10GBaseT:
		printf(" 10G BaseT");
		break;
	case DOT3MAUTYPE_10GBaseLRM:
		printf(" 10G BaseLRM");
		break;
	case DOT3MAUTYPE_1000BaseKX:
		printf(" 1000 BaseKX");
		break;
	case DOT3MAUTYPE_10GBaseKX4:
		printf(" 10G BaseKX4");
		break;
	case DOT3MAUTYPE_10GBaseKR:
		printf(" 10G BaseKR");
		break;
	case DOT3MAUTYPE_10_1GBasePRXD1:
		printf(" 10/1G BasePRXD1");
		break;
	case DOT3MAUTYPE_10_1GBasePRXD2:
		printf(" 10/1G BasePRXD2");
		break;
	case DOT3MAUTYPE_10_1GBasePRXD3:
		printf(" 10/1G BasePRXD3");
		break;
	case DOT3MAUTYPE_10_1GBasePRXU1:
		printf(" 10/1G BasePRXU1");
		break;
	case DOT3MAUTYPE_10_1GBasePRXU2:
		printf(" 10/1G BasePRXU2");
		break;
	case DOT3MAUTYPE_10_1GBasePRXU3:
		printf(" 10/1G BasePRXU3");
		break;
	case DOT3MAUTYPE_10GBasePRD1:
		printf(" 10G BasePRD1");
		break;
	case DOT3MAUTYPE_10GBasePRD2:
		printf(" 10G BasePRD2");
		break;
	case DOT3MAUTYPE_10GBasePRD3:
		printf(" 10G BasePRD3");
		break;
	case DOT3MAUTYPE_10GBasePRU1:
		printf(" 10G BasePRU1");
		break;
	case DOT3MAUTYPE_10GBasePRU3:
		printf(" 10G BasePRU3");
		break;
	case DOT3MAUTYPE_40GBaseKR4:
		printf(" 40G BaseKR4");
		break;
	case DOT3MAUTYPE_40GBaseCR4:
		printf(" 40G BaseCR4");
		break;
	case DOT3MAUTYPE_40GBaseSR4:
		printf(" 40G BaseSR4");
		break;
	case DOT3MAUTYPE_40GBaseFR:
		printf(" 40G BaseFR");
		break;
	case DOT3MAUTYPE_40GBaseLR4:
		printf(" 40G BaseLR4");
		break;
	case DOT3MAUTYPE_100GBaseCR10:
		printf(" 100G BaseCR10");
		break;
	case DOT3MAUTYPE_100GBaseSR10:
		printf(" 100G BaseSR10");
		break;
	case DOT3MAUTYPE_100GBaseLR4:
		printf(" 100G BaseLR4");
		break;
	case DOT3MAUTYPE_100GBaseER4:
		printf(" 100G BaseER4");
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

	printf("Port class %s\n\t", (mdi_power & 0x01) ? "PSE" : "PD");
	printf("PSE MDI power %ssupported\n\t",
	       (mdi_power & 0x02) ? "" : "not ");
	if (mdi_power & 0x02)
		printf(" and %s", (mdi_power & 0x04) ? "enabled" : "disabled");
	printf("PSE pairs %scontrollable\n\t",
	       (mdi_power & 0x08) ? "" : "not ");

	/* pethPsePortPowerPair - IETF RFC 3621 */
	printf("PSE Power pair: ");
	if (pse_power == 1)
		printf("signal");
	else if (pse_power == 2)
		printf("spare");
	else
		printf("unkwown [%d]", pse_power);
	printf("\n\t");

	/* pethPsePortPowerClassifications - IETF RFC 3621 */
	printf("Power class %d\n", power_class+1);
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

void print_mtu(UNUSED u16 len, char *info)
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
