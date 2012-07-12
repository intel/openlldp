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
#include "lldp.h"
#include "lldp_mod.h"
#include "lldptool.h"
#include "clif_msgs.h"
#include "lldp_med.h"
#include "lldp_med_clif.h"

void med_print_string_tlv(u16, char *info);
void med_print_cap_tlv(u16, char *info);
void med_print_hex_tlv(u16, char *info);
u32 med_lookup_tlv_name(char *tlvid_str);
int med_print_help();

static const struct lldp_mod_ops med_ops_clif = {
	.lldp_mod_register 	= med_cli_register,
	.lldp_mod_unregister 	= med_cli_unregister,
	.print_tlv		= med_print_tlv,
	.lookup_tlv_name	= med_lookup_tlv_name,
	.print_help		= med_print_help,
};

struct type_name_info med_tlv_names[] = {
	{	.type = (OUI_TIA_TR41 << 8),
		.name = "LLDP-MED Settings", .key = "LLDP-MED", },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_CAPABILITIES,
		.name = "LLDP-MED Capabilities TLV", .key = "medCap",
		.print_info = med_print_cap_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_NETWORK_POLICY,
		.name = "LLDP-MED Network Policy TLV", .key = "medPolicy",
		.print_info = med_print_hex_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_LOCATION_ID,
		.name = "LLDP-MED Location TLV", .key = "medLoc",
		.print_info = med_print_hex_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_EXTENDED_PVMDI,
		.name = "LLDP-MED Extended Power-via-MDI TLV",
		.key = "medPower",
		.print_info = med_print_hex_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_HWREV,
		.name = "LLDP-MED Hardware Revision TLV", .key = "medHwRev",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_FWREV,
		.name = "LLDP-MED Firmware Revision TLV", .key = "medFwRev",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SWREV,
		.name = "LLDP-MED Software Revision TLV", .key = "medSwRev",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_SERIAL,
		.name = "LLDP-MED Serial Number TLV", .key = "medSerNum",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MANUFACTURER,
		.name = "LLDP-MED Manufacturer Name TLV", .key = "medManuf",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_MODELNAME,
		.name = "LLDP-MED Model Name TLV", .key = "medModel",
		.print_info = med_print_string_tlv, },
	{	.type = (OUI_TIA_TR41 << 8) | LLDP_MED_INV_ASSETID,
		.name = "LLDP-MED Asset ID TLV", .key = "medAssetID",
		.print_info = med_print_string_tlv, },
	{	.type = INVALID_TLVID, }
};

int med_print_help()
{
	struct type_name_info *tn = &med_tlv_names[0];

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

struct lldp_module *med_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		goto out_err;
	}
 	mod->id = LLDP_MOD_MED;
	mod->ops = &med_ops_clif;

	return mod;
out_err:
	return NULL;
}

void med_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

void med_print_cap_tlv(u16 len, char *info)
{
	u16 caps;
	u8 devtype;
	char *s;
	int i;
	int print_comma;

	if (len != 3) {
		printf("Bad LLDP-MED Capabilities TLV: %*.*s\n",
			2*len, 2*len, info);
		return;
	}

	hexstr2bin(info, (u8 *)&caps, sizeof(caps));
	caps = ntohs(caps);
	hexstr2bin(info+4, (u8 *)&devtype, sizeof(devtype));

	switch (devtype) {
	case LLDP_MED_DEVTYPE_NOT_DEFINED:
		s = VAL_MED_NOT;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_I:
		s = VAL_MED_CLASS_I;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_II:
		s = VAL_MED_CLASS_II;
		break;
	case LLDP_MED_DEVTYPE_ENDPOINT_CLASS_III:
		s = VAL_MED_CLASS_III;
		break;
	case LLDP_MED_DEVTYPE_NETWORK_CONNECTIVITY:
		s = VAL_MED_NETCON;
		break;
	default:
		s = VAL_MED_NOT;
		break;
	}

	printf("Device Type:  %s\n\tCapabilities: ", s);

	print_comma = 0;
	for (i = 0; i < 16; i++) {
		switch ((1<<i) & caps) {
		case 0x01:
			printf("%sLLDP-MED", print_comma ? ", " : "");
			print_comma = 1;
			break;
		case 0x02:
			printf("%sNetwork Policy", print_comma ? ", " : "");
			print_comma = 1;
			break;
		case 0x04:
			printf("%sLocation Identification",
				print_comma ? ", " : "");
			print_comma = 1;
			break;
		case 0x08:
			printf("%sExtended Power via MDI-PSE",
				print_comma ? ", " : "");
			print_comma = 1;
			break;
		case 0x10:
			printf("%sExtended Power via MDI-PD",
				print_comma ? ", " : "");
			print_comma = 1;
			break;
		case 0x20:
			printf("%sInventory", print_comma ? ", " : "");
			print_comma = 1;
			break;
		}
	}
	if (!print_comma)
		printf("none");
	printf("\n");
}

void med_print_hex_tlv(u16 len, char *info)
{
	printf("%*.*s\n", 2*len, 2*len, info);
}

void med_print_string_tlv(u16 len, char *info)
{
	int i;
	for (i = 0; i < 2*len; i+=2)
		printf("%c", hex2int(info+i));
	printf("\n");
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int med_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &med_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n\t", tn->name);
			if (tn->print_info)
				tn->print_info(len-4, info);
			return 1;
		}
		tn++;
	}
	
	return 0;
}

u32 med_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &med_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}
