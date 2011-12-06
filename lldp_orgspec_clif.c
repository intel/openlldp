/*******************************************************************************

  Implementation of Organisation Specific TLVs for LLDP
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
#include "lldptool.h"
#include "lldp.h"
#include "lldp_orgspec_clif.h"

static void orgspec_print_pvid_tlv(u16 len, char *info);
static void orgspec_print_ppvid_tlv(u16 len, char *info);
static void orgspec_print_vlan_name_tlv(u16 len, char *info);
static void orgspec_print_protoid_tlv(u16 len, char *info);
static void orgspec_print_vid_usage_tlv(u16 len, char *info);
static void orgspec_print_mgmt_vid_tlv(u16 len, char *info);
static void orgspec_print_link_aggr_tlv(u16 len, char *info);
static int orgspec_print_help();

u32 orgspec_lookup_tlv_name(char *tlvid_str);

static const struct lldp_mod_ops orgspec_ops_clif = {
	.lldp_mod_register	= orgspec_cli_register,
	.lldp_mod_unregister	= orgspec_cli_unregister,
	.print_tlv		= orgspec_print_tlv,
	.lookup_tlv_name	= orgspec_lookup_tlv_name,
	.print_help		= orgspec_print_help,
};

struct type_name_info orgspec_tlv_names[] = {
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_PVID,
		"Port VLAN ID TLV",
		"PVID", orgspec_print_pvid_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_PPVID,
		"Port and Protocol VLAN ID TLV",
		"PPVID", orgspec_print_ppvid_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_VLAN_NAME,
		"VLAN Name TLV",
		"vlanName", orgspec_print_vlan_name_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_PROTO_ID,
		"Protocol Identity TLV",
		"ProtoID", orgspec_print_protoid_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_VID_USAGE,
		"VID Usage Digest TLV",
		"vidUsage", orgspec_print_vid_usage_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_MGMT_VID,
		"Management VID TLV",
		"mgmtVID", orgspec_print_mgmt_vid_tlv },
	{ (OUI_IEEE_8021 << 8) | ORG_SPEC_LINK_AGGR,
		"Link Aggregation TLV",
		"linkAggr", orgspec_print_link_aggr_tlv },
	{ INVALID_TLVID,     NULL,        NULL }
};

static int orgspec_print_help()
{
	struct type_name_info *tn = &orgspec_tlv_names[0];

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

struct lldp_module *orgspec_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		return NULL;
	}
	mod->id = OUI_IEEE_8021;
	mod->ops = &orgspec_ops_clif;

	return mod;
}

void orgspec_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

static void orgspec_print_pvid_tlv(u16 len, char *info)
{
	u16 pvid;

	if (len != 2) {
		printf("Bad PVID TLV: %s\n", info);
		return;
	}
	if (hexstr2bin(info, (u8 *)&pvid, sizeof(pvid))) {
		printf("Unable to decode PVID !\n");
		return;
	}
	pvid = ntohs(pvid);
	if (pvid == 0)
		printf("PVID: unsupported");
	else
		printf("PVID: %d", pvid);
	printf("\n");
}

static void orgspec_print_ppvid_tlv(u16 len, char *info)
{
	u16 pvid;
	u8 flags;

	if (len != 3) {
		printf("Bad PPVID TLV: %s\n", info);
		return;
	}

	if (hexstr2bin(info, &flags, sizeof(flags))) {
		printf("Unable to decode PVID flags !\n");
		return;
	}
	if (flags & 2 && !(flags & 1)) {
		printf("Error decoding ppvid, discard\n");
		return;
	}
	if (hexstr2bin(info + 2, (u8 *)&pvid, sizeof(pvid))) {
		printf("Unable to decode PVID !\n");
		return;
	}
	printf("PVID: %x,%s supported,%s enabled",
	       ntohs(pvid), flags&1 ? "" : " not",
	       flags & 2 ? "" : " not");
	printf("\n");
}

static void orgspec_print_vlan_name_tlv(u16 len, char *info)
{
	u16 vid;
	u8 name_len;
	unsigned char vlan_name[32];

	if (len < 4) {
		printf("Bad VLAN Name TLV: %s\n", info);
		return;
	}

	if (hexstr2bin(info, (u8 *)&vid, sizeof(vid))) {
		printf("Unable to decode VID !\n");
		return;
	}

	if (hexstr2bin(info + 4, &name_len, sizeof(name_len)))
		name_len = 0;

	if (!hexstr2bin(info + 6, vlan_name, name_len - 1))
		printf("VID %d: Name %s", ntohs(vid), vlan_name);

	printf("\n");
}

static void orgspec_print_protoid_tlv(u16 len, char *info)
{
	u8 protoid_len;
	unsigned char protoid[256];
	int i;

	if (len < 4) {
		printf("Bad Protocol Identity TLV: %s\n", info);
		return;
	}

	if (hexstr2bin(info, (u8 *)&protoid_len, sizeof(protoid_len))) {
		printf("Unable to decode VID !\n");
		return;
	}

	if (!hexstr2bin(info + 2, protoid, protoid_len - 1)) {
		for (i = 0; i < protoid_len; i++)
			printf("%02x.", protoid[i]);
	}
	printf("\n");
}

static void orgspec_print_vid_usage_tlv(u16 len, char *info)
{
	u16 vid;
	u8 name_len;
	unsigned char vlan_name[32];

	if (len < 4) {
		printf("Bad VLAN Name TLV: %s\n", info);
		return;
	}

	if (hexstr2bin(info, (u8 *)&vid, sizeof(vid))) {
		printf("Unable to decode VID !\n");
		return;
	}

	if (hexstr2bin(info + 4, &name_len, sizeof(name_len)))
		name_len = 0;

	if (!hexstr2bin(info + 6, vlan_name, name_len - 1))
		printf("VID %d: Name %s", ntohs(vid), vlan_name);

	printf("\n");
}

static void orgspec_print_mgmt_vid_tlv(u16 len, char *info)
{
	u16 mgmt_vid;

	if (len != 2) {
		printf("Bad Mgmt VID TLV: %s\n", info);
		return;
	}
	if (hexstr2bin(info, (u8 *)&mgmt_vid, sizeof(mgmt_vid))) {
		printf("Unable to decode PVID !\n");
		return;
	}
	mgmt_vid = ntohs(mgmt_vid);
	if (mgmt_vid == 0)
		printf("Mgmt VID: unsupported\n");
	else
		printf("Mgmt VID: %d\n", mgmt_vid);
}

static void orgspec_print_link_aggr_tlv(u16 len, char *info)
{
	u8 agg_status;
	u32 agg_portid;

	if (len != 5) {
		printf("Bad Link Aggregation TLV: %s\n", info);
		return;
	}

	if (hexstr2bin(info, (u8 *)&agg_status, sizeof(agg_status))) {
		printf("Unable to decode Link Aggregation TLV !\n");
		return;
	}

	if (!hexstr2bin(info + 2, (u8 *)&agg_portid, sizeof(agg_portid))) {
		printf("Aggregation %scapable\n",
		       (agg_status & 0x01) ? "" : "not ");
		printf("\tCurrently %saggregated\n",
		       (agg_status & 0x02) ? "" : "not ");
		printf("\tAggregated Port ID: %d\n", ntohl(agg_portid));
	}
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int orgspec_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &orgspec_tlv_names[0];

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

u32 orgspec_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &orgspec_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}

