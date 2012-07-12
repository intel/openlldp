/******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>
  Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>

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

******************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "lldp_tlv.h"
#include "clif_msgs.h"
#include "lldp_mod.h"
#include "lldptool.h"
#include "lldp.h"
#include "lldp_evb.h"
#include "lldp_evb_clif.h"

static void evb_print_cfg_tlv(u16, char *);

static struct type_name_info evb_tlv_names[] = {
	{
		.type = TLVID_8021Qbg(LLDP_EVB_SUBTYPE),
		.name = "EVB Configuration TLV",
		.key = "evbCfg",
		.print_info = evb_print_cfg_tlv
	},
	{
		.type = INVALID_TLVID
	}
};

static int evb_print_help()
{
	struct type_name_info *tn = &evb_tlv_names[0];

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

static void evb_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

static void evb_print_cfg_tlv(u16 len, char *info)
{
	u8 smode;
	u8 scap;
	u8 cmode;
	u8 ccap;
	u16 svsi;
	u16 cvsi;
	u8 rte;

	if (len != 9) {
		printf("Bad Cfg TLV: %s\n", info);
		return;
	}

	if (!hexstr2bin(info, &smode, sizeof(smode))) {
		printf("supported forwarding mode: (%#x)", smode);

		if (smode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)
			printf(" reflective relay");

		if (smode & LLDP_EVB_CAPABILITY_FORWARD_STANDARD)
			printf(" standard 802.1Q");

		printf("\n");
	} else
		printf("Unable to decode smode !\n");

	if (!hexstr2bin(info+2, &scap, sizeof(scap))) {
		printf("\tsupported capabilities: (%#02hhx)", scap);

		if ( scap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE)
		     printf(" RTE");

		if ( scap & LLDP_EVB_CAPABILITY_PROTOCOL_ECP)
		     printf(" ECP");

		if ( scap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP)
		     printf(" VDP");

		printf("\n");
	} else
		printf("Unable to decode scap !\n");

	if (!hexstr2bin(info+4, &cmode, sizeof(cmode))) {
		printf("\tconfigured forwarding mode: (%#02hhx)", cmode);

		if (cmode & LLDP_EVB_CAPABILITY_FORWARD_REFLECTIVE_RELAY)
			printf(" reflective relay");

		if (cmode & LLDP_EVB_CAPABILITY_FORWARD_STANDARD)
			printf(" standard 802.1Q");

		printf("\n");
	} else
		printf("Unable to decode cmode !\n");

	if (!hexstr2bin(info+6, &ccap, sizeof(ccap))) {
		printf("\tconfigured capabilities: (%#02hhx)", ccap);

		if ( ccap & LLDP_EVB_CAPABILITY_PROTOCOL_RTE)
		     printf(" RTE");

		if ( ccap & LLDP_EVB_CAPABILITY_PROTOCOL_ECP)
		     printf(" ECP");

		if ( ccap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP)
		     printf(" VDP");

		printf("\n");
	} else
		printf("Unable to decode ccap !\n");

	if (!hexstr2bin(info+8, (u8 *)&svsi, sizeof(svsi)))
		printf("\tno. of supported VSIs: %04i\n", ntohs(svsi));
	else
		printf("Unable to decode svsi !\n");

	if (!hexstr2bin(info+12, (u8 *)&cvsi, sizeof(cvsi)))
		printf("\tno. of configured VSIs: %04i\n", ntohs(cvsi));
	else
		printf("Unable to decode cvsi !\n");

	if (!hexstr2bin(info+16, &rte, sizeof(rte)))
		printf("\tRTE: %i\n",rte);
	else
		printf("Unable to decode cvsi !\n");

	printf("\n");
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
static int evb_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &evb_tlv_names[0];

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

static u32 evb_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &evb_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}

static const struct lldp_mod_ops evb_ops_clif = {
	.lldp_mod_register	= evb_cli_register,
	.lldp_mod_unregister	= evb_cli_unregister,
	.print_tlv		= evb_print_tlv,
	.lookup_tlv_name	= evb_lookup_tlv_name,
	.print_help		= evb_print_help,
};

struct lldp_module *evb_cli_register(void)
{
	struct lldp_module *mod;

	mod = calloc(1, sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "%s failed to malloc module data\n", __func__);
		return NULL;
	}
	mod->id = LLDP_MOD_EVB;
	mod->ops = &evb_ops_clif;

	return mod;
}
