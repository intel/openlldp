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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "lldp.h"
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp_8021qaz.h"
#include "lldp_8021qaz_clif.h"

static void ieee8021qaz_print_etscfg_tlv(u16 len, char *info);
static void ieee8021qaz_print_etsrec_tlv(u16 len, char *info);
static void ieee8021qaz_print_pfc_tlv(u16 len, char *info);
static void ieee8021qaz_print_app_tlv(u16 len, char *info);
static u32 ieee8021qaz_lookup_tlv_name(char *tlvid_str);
static int ieee8021qaz_print_help(void);

static const struct lldp_mod_ops ieee8021qaz_ops_clif = {
	.lldp_mod_register      = ieee8021qaz_cli_register,
	.lldp_mod_unregister    = ieee8021qaz_cli_unregister,
	.print_tlv		= ieee8021qaz_print_tlv,
	.lookup_tlv_name	= ieee8021qaz_lookup_tlv_name,
	.print_help		= ieee8021qaz_print_help,
};

struct type_name_info ieee8021qaz_tlv_names[] = {
	{
		.type = (OUI_IEEE_8021 << 8),
		.name = "IEEE-DCBX Settings", .key = "IEEE-DCBX",
	},
	{
		.type = (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSCFG,
		.name = "IEEE 8021QAZ ETS Configuration TLV", .key = "ETS-CFG",
		.print_info = ieee8021qaz_print_etscfg_tlv,
	},
	{
		.type = (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_ETSREC,
		.name = "IEEE 8021QAZ ETS Recommendation TLV", .key = "ETS-REC",
		.print_info = ieee8021qaz_print_etsrec_tlv,
	},
	{
		.type = (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_PFC,
		.name = "IEEE 8021QAZ PFC TLV",	.key = "PFC",
		.print_info = ieee8021qaz_print_pfc_tlv,
	},
	{
		.type = (OUI_IEEE_8021 << 8) | LLDP_8021QAZ_APP,
		.name = "IEEE 8021QAZ APP TLV",	.key = "APP",
		.print_info = ieee8021qaz_print_app_tlv,
	},
	{	.type = INVALID_TLVID, }
};

static int ieee8021qaz_print_help(void)
{
	struct type_name_info *tn = &ieee8021qaz_tlv_names[0];

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

struct lldp_module *ieee8021qaz_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod)
		return NULL;

	mod->id = LLDP_MOD_8021QAZ;
	mod->ops = &ieee8021qaz_ops_clif;

	return mod;
}

void ieee8021qaz_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

static void ieee8021qaz_print_etscfg_tlv(UNUSED u16 len, char *info)
{
	u8 wc_maxtc;
	u8 tc_bw[8], tsa_map[8];
	u32 prio_map;
	int offset = 0, i = 0;

	hexstr2bin(info, (u8 *)&wc_maxtc, 1);

	printf(" Willing: %s\n", (wc_maxtc & 0x80) ? "yes" : "no");
	printf("\t CBS: %s\n",
	       (wc_maxtc & 0x40) ? "supported" : "not supported");
	if (!(wc_maxtc & 0x7))
		printf("\t MAX_TCS: 8\n");
	else
		printf("\t MAX_TCS: %i\n", wc_maxtc & 0x7);

	offset += 2;
	hexstr2bin(info + offset, (u8 *)&prio_map, 4);
	prio_map = ntohl(prio_map);

	printf("\t PRIO_MAP: ");
	for (i = 0; i < 8; i++)
		printf("%i:%i ", i, (prio_map >> ((7-i)*4)) & 0xf);
	printf("\n");

	offset += 8;
	hexstr2bin(info + offset, tc_bw, 8);
	printf("\t TC Bandwidth: ");
	for (i = 0; i < MAX_TCS; i++)
		printf("%i%% ", tc_bw[i]);
	printf("\n");

	offset += 16;
	hexstr2bin(info + offset, (u8 *)tsa_map, 8);
	printf("\t TSA_MAP: ");
	for (i = 0; i < MAX_TCS; i++) {
		printf("%i:", i);
		switch (tsa_map[i]) {
		case IEEE8021Q_TSA_STRICT:
			printf("strict ");
			break;
		case IEEE8021Q_TSA_CBSHAPER:
			printf("cbshaper ");
			break;
		case IEEE8021Q_TSA_ETS:
			printf("ets ");
			break;
		case IEEE8021Q_TSA_VENDOR:
			printf("vendor ");
			break;
		default:
			printf("unknown ");
			break;
		}
	}
	printf("\n");
}

static void ieee8021qaz_print_etsrec_tlv(UNUSED u16 len, char *info)
{
	u8 offset = 0;
	u32 prio_map;
	u8 tc_bw[8], tsa_map[8];
	int i = 0;

	/* advanced past initial 8bit reserved field */
	offset += 2;

	hexstr2bin(info + offset, (u8 *)&prio_map, 4);
	prio_map = ntohl(prio_map);
	printf(" PRIO_MAP:  ");
	for (i = 0; i < 8; i++)
		printf("%i:%i ", i, (prio_map >> ((7-i)*4)) & 0xf);
	printf("\n");

	offset += 8;
	hexstr2bin(info + offset, tc_bw, 8);
	printf("\t TC Bandwidth: ");
	for (i = 0; i < MAX_TCS; i++)
		printf("%i%% ", tc_bw[i]);
	printf("\n");

	offset += 16;
	hexstr2bin(info + offset, (u8 *)tsa_map, 8);
	printf("\t TSA_MAP: ");
	for (i = 0; i < MAX_TCS; i++) {
		printf("%i:", i);
		switch (tsa_map[i]) {
		case IEEE8021Q_TSA_STRICT:
			printf("strict ");
			break;
		case IEEE8021Q_TSA_CBSHAPER:
			printf("cbshaper ");
			break;
		case IEEE8021Q_TSA_ETS:
			printf("ets ");
			break;
		case IEEE8021Q_TSA_VENDOR:
			printf("vendor ");
			break;
		default:
			printf("unknown ");
			break;
		}
	}
	printf("\n");
}

static void ieee8021qaz_print_pfc_tlv(UNUSED u16 len, char *info)
{
	int i, offset = 0;
	u8 w_mbc_cap, pfc_enable;
	u8 found = 0;

	hexstr2bin(info + offset, (u8 *)&w_mbc_cap, 1);
	printf(" Willing: %s\n", (w_mbc_cap & 0x80) ? "yes" : "no");
	printf("\t MACsec Bypass Capable: %s\n",
		(w_mbc_cap & 0x40) ? "yes" : "no");
	printf("\t PFC capable traffic classes: %i\n", w_mbc_cap & 0x0f);

	offset += 2;
	printf("\t PFC enabled: ");
	hexstr2bin(info + offset, (u8 *)&pfc_enable, 1);
	for (i = 0; i < 8; i++) {
		if ((pfc_enable >> i) & 1) {
			found = 1;
			printf("%i ", i);
		}
	}
	if (!found)
		printf("none");
	printf("\n");
}

static void ieee8021qaz_print_app_tlv(u16 len, char *info)
{
	u8 offset = 2;
	u8 app;
	u16 proto;

	while (offset < len*2) {
		hexstr2bin(info + offset, &app, 1);
		hexstr2bin(info + offset + 2, (u8 *)&proto, 2);

		if (offset > 6)
			printf("\t");
		printf("App#%i:\n", offset/6);
		printf("\t Priority: %i\n", (app & 0xE0) >> 5);
		printf("\t Sel: %i\n", app & 0x07);
		switch (app & 0x07) {
		case 1:
			printf("\t Ethertype: 0x%04x\n", ntohs(proto));
			break;
		case 2:
			printf("\t {S}TCP Port: %i\n", ntohs(proto));
			break;
		case 3:
			printf("\t UDP or DCCP Port: %i\n", ntohs(proto));
			break;
		case 4:
			printf("\t TCP/STCP/UDP/DCCP Port: %i\n", ntohs(proto));
			break;
		default:
			printf("\t Reserved Port: %i\n", ntohs(proto));
			break;
		}

		printf("\n");
		offset += 6;
	}
}

int ieee8021qaz_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &ieee8021qaz_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n\t", tn->name);
			if (tn->print_info)
				tn->print_info(len - 4, info);
			return 1;
		}
		tn++;
	}

	return 0;
}

static u32 ieee8021qaz_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &ieee8021qaz_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}

	return INVALID_TLVID;
}
