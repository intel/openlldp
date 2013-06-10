/*******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens@linux.vnet.ibm.com>
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
#include <sys/stat.h>
#include "lldp_mod.h"
#include "clif_msgs.h"
#include "lldp.h"
#include "qbg_vdp.h"
#include "qbg_vdp_cmds.h"
#include "qbg_vdp_clif.h"
#include "lldp_mand_clif.h"

static const char *mode_state(int mode)
{
	switch (mode) {
	case VDP_MODE_PREASSOCIATE_WITH_RR:
		return "Preassociated with RR";
	case VDP_MODE_DEASSOCIATE:
		return "Disassociated";
	case VDP_MODE_ASSOCIATE:
		return "Associated";
	case VDP_MODE_PREASSOCIATE:
		return "Preassociated";
	default: return "unknown";
	}
}

/*
 * Print a complete VDP TLV. Data string constructed in function
 * vdp_clif_profile().
 */
static void vdp_show_tlv(UNUSED u16 len, char *info)
{
	int rc, role, enabletx, vdpbit, mode, response, mgrid, id, idver;
	unsigned int x[16];

	rc = sscanf(info, "%02x%02x%02x%02x%02x%02x%06x%02x",
		    &role, &enabletx, &vdpbit, &mode, &response, &mgrid,
		    &id, &idver);
	if (rc != 3 && rc != 8)
		return;
	printf("Role:%s\n", role ? VAL_BRIDGE : VAL_STATION);
	printf("\tEnabled:%s\n", enabletx ? VAL_YES : VAL_NO);
	printf("\tVDP Bit:%s\n", vdpbit ? VAL_YES : VAL_NO);
	if (rc == 3)		/* No active VSI profile */
		return;
	printf("\tMode:%d (%s)\n", mode, mode_state(mode));
	printf("\tMgrid:%d\n", mgrid);
	printf("\tTypeid:%d\n", id);
	printf("\tTypeidversion:%d\n", idver);
	rc = sscanf(info + 20, "%02x%02x%02x%02x%02x%02x%02x%02x"
		    "%02x%02x%02x%02x%02x%02x%02x%02x",
		    &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7],
		    &x[8], &x[9], &x[10], &x[11], &x[12], &x[13], &x[14],
		    &x[15]);
	if (rc != 16)
		return;
	printf("\tUUID:%02x%02x%02x%02x-%02x%02x-%02x%02x"
	       "-%02x%02x-%02x%02x%02x%02x%02x%02x\n", x[0], x[1], x[2], x[3],
	       x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13],
	       x[14], x[15]);
	mode = 52;
	rc = sscanf(info + mode, "%02x%04x", &role, &vdpbit);
	if (rc != 2)
		return;
	printf("\tFilter Format:%d\n", role);
	printf("\tEntries:%d\n", vdpbit);
	mode += 6;
	while (--vdpbit >= 0) {
		rc = sscanf(info + mode, "%02x%02x%02x%02x%02x%02x%04x",
			    &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6]);
		if (rc != 7)
			return;
		printf("\t\tMAC:%02x:%02x:%02x:%02x:%02x:%02x\tVlanid:%d\n",
		       x[0], x[1], x[2], x[3], x[4], x[5], x[6]);
		mode += 16;
	}
}

static struct type_name_info vdp_tlv_names[] = {
	{
		.type = ((LLDP_MOD_VDP) << 8) | LLDP_VDP_SUBTYPE,
		.name = "VDP draft 0.2 protocol configuration",
		.key = "vdp",
		.print_info = vdp_show_tlv
	},
	{
		.type = INVALID_TLVID
	}
};

static int vdp_print_help()
{
       struct type_name_info *tn = &vdp_tlv_names[0];

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

static u32 vdp_lookup_tlv_name(char *tlvid_str)
{
       struct type_name_info *tn = &vdp_tlv_names[0];

       while (tn->type != INVALID_TLVID) {
               if (!strcasecmp(tn->key, tlvid_str))
                       return tn->type;
               tn++;
       }
       return INVALID_TLVID;
}

static void vdp_cli_unregister(struct lldp_module *mod)
{
       free(mod);
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
static int vdp_print_tlv(u32 tlvid, u16 len, char *info)
{
       struct type_name_info *tn = &vdp_tlv_names[0];

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

static const struct lldp_mod_ops vdp_ops_clif = {
       .lldp_mod_register      = vdp_cli_register,
       .lldp_mod_unregister    = vdp_cli_unregister,
       .print_tlv              = vdp_print_tlv,
       .lookup_tlv_name        = vdp_lookup_tlv_name,
       .print_help             = vdp_print_help,
};

struct lldp_module *vdp_cli_register(void)
{
       struct lldp_module *mod;

       mod = malloc(sizeof(*mod));
       if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		return NULL;
       }
       mod->id = (LLDP_MOD_VDP << 8) | LLDP_VDP_SUBTYPE;
       mod->ops = &vdp_ops_clif;
       return mod;
}
