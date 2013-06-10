/******************************************************************************

  Implementation of EVB TLVs for LLDP
  (c) Copyright IBM Corp. 2010, 2012

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
#include "lldp_evb22.h"
#include "lldp_evb22_clif.h"

static void show_tlv(char *buf, size_t len, struct evb22_tlv *tlv)
{
	int comma = 0;
	char bridge_txt[32], station_txt[32];

	memset(bridge_txt, 0, sizeof bridge_txt);
	if (evb_ex_bgid(tlv->bridge_s)) {
		strcat(bridge_txt, "bgid");
		comma = 1;
	}
	if (evb_ex_rrcap(tlv->bridge_s)) {
		if (comma)
			strcat(bridge_txt, ",");
		strcat(bridge_txt, "rrcap");
		comma = 1;
	}
	if (evb_ex_rrctr(tlv->bridge_s)) {
		if (comma)
			strcat(bridge_txt, ",");
		strcat(bridge_txt, "rrctr");
	}

	comma = 0;
	memset(station_txt, 0, sizeof station_txt);
	if (evb_ex_sgid(tlv->station_s)) {
		strcat(station_txt, "sgid");
		comma = 1;
	}
	if (evb_ex_rrreq(tlv->station_s)) {
		if (comma)
			strcat(station_txt, ",");
		strcat(station_txt, "rrreq");
		comma = 1;
	}
	if (evb_ex_rrstat(tlv->station_s)) {
		if (comma)
			strcat(station_txt, ",");
		strcat(station_txt, "rrstat");
	}

	snprintf(buf, len, "bridge:%s(%#02x)\n"
		 "\tstation:%s(%#02x)\n"
		 "\tretries:%d rte:%d\n"
		 "\tmode:%s r/l:%d rwd:%d\n"
		 "\tr/l:%d rka:%d\n",
		 bridge_txt, tlv->bridge_s,
		 station_txt, tlv->station_s,
		 evb_ex_retries(tlv->r_rte), evb_ex_rte(tlv->r_rte),
		 evb_ex_evbmode(tlv->evb_mode) == EVB_STATION ?
			"station" : "bridge",
		 evb_ex_rol(tlv->evb_mode),
		 evb_ex_rwd(tlv->evb_mode),
		 evb_ex_rol(tlv->rl_rka), evb_ex_rka(tlv->rl_rka));
}

static void evb22_print_cfg_tlv(u16 len, char *info)
{
	struct evb22_tlv tlv;
	char buf[256];

	if (len != 5) {
		printf("Bad evbcfg TLV: %s\n", info);
		return;
	}
	memset(&tlv, 0, sizeof tlv);
	memset(buf, 0, sizeof buf);
	hexstr2bin(&info[0], &tlv.bridge_s, sizeof tlv.bridge_s);
	hexstr2bin(&info[2], &tlv.station_s, sizeof tlv.station_s);
	hexstr2bin(&info[4], &tlv.r_rte, sizeof tlv.r_rte);
	hexstr2bin(&info[6], &tlv.evb_mode, sizeof tlv.evb_mode);
	hexstr2bin(&info[8], &tlv.rl_rka, sizeof tlv.rl_rka);
	show_tlv(buf, sizeof buf, &tlv);
	printf("%s", buf);
}

static struct type_name_info evb22_tlv_names[] = {
	{
		.type = TLVID(OUI_IEEE_8021Qbg22, LLDP_EVB22_SUBTYPE),
		.name = "EVB Configuration TLV",
		.key = "evb",
		.print_info = evb22_print_cfg_tlv
	},
	{
		.type = INVALID_TLVID
	}
};

static int evb22_print_help()
{
	struct type_name_info *tn = &evb22_tlv_names[0];

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

static void evb22_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
static int evb22_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &evb22_tlv_names[0];

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

static u32 evb22_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &evb22_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}

static const struct lldp_mod_ops evb22_ops_clif = {
	.lldp_mod_register	= evb22_cli_register,
	.lldp_mod_unregister	= evb22_cli_unregister,
	.print_tlv		= evb22_print_tlv,
	.lookup_tlv_name	= evb22_lookup_tlv_name,
	.print_help		= evb22_print_help
};

struct lldp_module *evb22_cli_register(void)
{
	struct lldp_module *mod;

	mod = calloc(1, sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "%s failed to malloc module data\n", __func__);
		return NULL;
	}
	mod->id = LLDP_MOD_EVB22;
	mod->ops = &evb22_ops_clif;

	return mod;
}
