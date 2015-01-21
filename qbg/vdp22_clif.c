/*******************************************************************************

  Implementation of VDP 22 (ratified standard) according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2014

  Author(s): Thomas Richter <tmricht@linux.vnet.ibm.com>

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

#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp.h"
#include "qbg22.h"
#include "qbg_vdp22def.h"
#include "qbg_vdpnl.h"
#include "qbg_vdp22_cmds.h"
#include "qbg_vdp22_clif.h"
#include "qbg_vdp22def.h"

static struct type_name_info vdp22_tlv_names[] = {
	{
		.name = "VDP VSI Association",
		.key = "assoc",
		.type = VDP22_ASSOC
	},
	{
		.name = "VDP VSI Deassociation",
		.key = "deassoc",
		.type = VDP22_DEASSOC
	},
	{
		.name = "VDP VSI Preassociation",
		.key = "preassoc",
		.type = VDP22_PREASSOC
	},
	{
		.name = "VDP VSI Preassociation with resource reservation",
		.key = "preassoc-rr",
		.type = VDP22_PREASSOC_WITH_RR
	},
	{
		.type = INVALID_TLVID
	}
};

static int vdp22_print_help(void)
{
	struct type_name_info *tn = &vdp22_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tn->key && strlen(tn->key) && tn->name) {
			printf("   %s", tn->key);
			if (strlen(tn->key) + 3 < 8)
				printf("\t");
			printf("\t: %s\n", tn->name);
		}
		tn++;
	}
	return 0;
}

static u32 vdp22_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &vdp22_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}

static void vdp22_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

/* return 1: if it printed the TLV
 *	  0: if it did not
 */
static int vdp22_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &vdp22_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n", tn->name);
			if (tn->print_info) {
				printf("\t");
				tn->print_info(len - 4, info);
			}
			return 1;
		}
		tn++;
	}
	return 0;
}

static const struct lldp_mod_ops vdp22_ops_clif = {
	.lldp_mod_register	= vdp22_cli_register,
	.lldp_mod_unregister	= vdp22_cli_unregister,
	.print_tlv		= vdp22_print_tlv,
	.lookup_tlv_name	= vdp22_lookup_tlv_name,
	.print_help		= vdp22_print_help,
};

struct lldp_module *vdp22_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		return NULL;
	}
	mod->id = LLDP_MOD_VDP22;
	mod->ops = &vdp22_ops_clif;
	return mod;
}
