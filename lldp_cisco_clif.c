/*******************************************************************************

  Implementation of Cisco Specific TLVs for LLDP
  (c) Copyright SuSE Linux Products GmbH, 2011

  Author(s): Hannes Reinecke <hare at suse dot de>

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
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp.h"
#include "lldp_cisco_clif.h"

static void cisco_print_upoe_tlv(u16 len, char *info);
static int cisco_print_help();

static u32 cisco_lookup_tlv_name(char *tlvid_str);

static const struct lldp_mod_ops cisco_ops_clif = {
	.lldp_mod_register	= cisco_cli_register,
	.lldp_mod_unregister	= cisco_cli_unregister,
	.print_tlv		= cisco_print_tlv,
	.lookup_tlv_name	= cisco_lookup_tlv_name,
	.print_help		= cisco_print_help,
};

struct type_name_info cisco_tlv_names[] = {
	{	.type = (OUI_CISCO << 8) | 1,
		.name = "Cisco 4-wire Power-via-MDI TLV", .key = "uPoE",
		.print_info = cisco_print_upoe_tlv },
	{	.type = INVALID_TLVID, }
};

static int cisco_print_help()
{
	struct type_name_info *tn = &cisco_tlv_names[0];

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

struct lldp_module *cisco_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		return NULL;
	}
	mod->id = OUI_IEEE_8021;
	mod->ops = &cisco_ops_clif;

	return mod;
}

void cisco_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

static void cisco_print_upoe_tlv(u16 len, char *info)
{
	u8 cap;

	if (len != 1) {
		printf("Bad uPoE TLV: %s\n", info);
		return;
	}
	if (!hexstr2bin(info, (u8 *)&cap, sizeof(cap))) {
		printf("4-Pair PoE %ssupported\n",
		       cap & 0x01 ? "" : "not ");
		printf("\tSpare pair Detection/Classification %srequired\n",
		       cap & 0x02 ? "" : "not ");
		printf("\tPD Spare pair Desired State: %s\n",
		       cap & 0x04 ? "Enabled" : "Disabled");
		printf("\tPSE Spare pair Operational State: %s\n",
		       cap & 0x08 ? "Enabled" : "Disabled");
	}
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int cisco_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &cisco_tlv_names[0];

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

static u32 cisco_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &cisco_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}

